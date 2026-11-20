#!/usr/bin/env python3
"""Deterministic tests for SDP-to-RTP UDP transport correlation."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
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
CLI = SCRIPTS / "correlate-sdp-rtp-transport.py"
KEY_CLI = SCRIPTS / "create-endpoint-key.py"
SCHEMA = SKILL / "schemas" / "sdp-rtp-transport-correlation.schema.json"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
TEST_DIR = Path(__file__).resolve().parent
SDP_SCRIPTS = SKILL.parents[1] / "protocol" / "sdp-rtp" / "scripts"
for path in (SCRIPTS, TEST_DIR, SDP_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402
import sdp_rtp_transport_model as model  # noqa: E402
import transport_fixture_builder as builder  # noqa: E402

KEY = builder.TEST_KEY
OTHER_KEY = hashlib.sha256(b"synthetic-other-endpoint-key").digest()


def _write(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def analyze_pair(sdp: dict, rtp: dict) -> dict:
    directory = Path(tempfile.mkdtemp())
    sdp_path = directory / "sdp.json"
    rtp_path = directory / "rtp.json"
    _write(sdp_path, sdp)
    _write(rtp_path, rtp)
    loaded_sdp = model.load_sdp_analysis(sdp_path)
    loaded_rtp = model.load_rtp_analysis(rtp_path)
    provenance = model.verify_provenance(
        loaded_sdp, loaded_rtp, sdp_path=sdp_path, rtp_path=rtp_path
    )
    document = model.build_analysis(loaded_sdp, loaded_rtp, provenance=provenance)
    model.validate_analysis(document)
    return document


def sdp_document(body: str, *, key: bytes | None = KEY, index: int = 1) -> dict:
    record = {
        "source_reference": f"sip-body:{builder.CAPTURE}:{index}.1",
        "capture_file": builder.CAPTURE,
        "capture_sha256": builder.SHA,
        "frame_number": index,
        "frame_reference": f"frame:{index}",
        "message_occurrence": 1,
        "sdp_body": body,
    }
    return sdp_model.build_analysis([record], endpoint_key=key)


def rtp_document(records: list[dict], *, key: bytes | None = KEY) -> dict:
    directory = Path(tempfile.mkdtemp())
    path = directory / "rtp-input.jsonl"
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    events, provenance = rtp_rtcp_model.extract_structured(path, endpoint_key=key)
    return rtp_rtcp_model.build_analysis(events, provenance)


def empty_rtp_document() -> dict:
    from endpoint_reference import endpoint_context_reference

    provenance = {
        "mode": "STRUCTURED_JSONL",
        "input_name": "empty-rtp-input.jsonl",
        "capture_files": [builder.CAPTURE],
        "capture_sha256": builder.SHA,
        "input_message_count": 0,
        "parser_version": rtp_rtcp_model.PARSER_VERSION,
        "tool": None,
        "decode_as": [],
        "endpoint_context_reference": endpoint_context_reference(KEY, builder.SHA),
    }
    return rtp_rtcp_model.build_analysis([], provenance)


def basic_sdp(address: str = "192.0.2.10", port: int = 49170) -> dict:
    body = (
        "v=0\r\n"
        f"o=- 1000 1 IN IP4 {address}\r\n"
        "s=Synthetic\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0\r\n"
    )
    return sdp_document(body)


def stream_packet(
    frame: int,
    *,
    stream: int,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int = 1,
    evidence: str = "OBSERVED",
) -> dict:
    return builder.rtp_record(
        frame,
        stream=stream,
        source_address=source,
        destination_address=destination,
        source_port=source_port,
        destination_port=destination_port,
        sequence_number=sequence,
        evidence=evidence,
    )


def correlations(document: dict, status: str | None = None) -> list[dict]:
    items = document["correlations"]
    if status is not None:
        items = [item for item in items if item["association_status"] == status]
    return items


def for_media(document: dict, media_index: int, message_suffix: str | None = None) -> dict:
    for correlation in document["correlations"]:
        for item in correlation["sdp_media_sections"]:
            if item["media_index"] != media_index:
                continue
            if message_suffix is not None and not item["message_reference"].endswith(message_suffix):
                continue
            return correlation
    raise AssertionError(f"no correlation for media index {media_index}")


class CorrelationMatchTests(unittest.TestCase):
    def test_01_unique_source_endpoint_match(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="192.0.2.10", destination="192.0.2.20", source_port=49170, destination_port=6000)]
        )
        document = analyze_pair(sdp, rtp)
        correlation = correlations(document, "MATCHED_ENDPOINT")[0]
        self.assertEqual(correlation["correlation_strength"], "STRONG")
        self.assertEqual(correlation["match_directions"], ["RTP_SOURCE_ENDPOINT_MATCH"])

    def test_02_unique_destination_endpoint_match(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170)]
        )
        document = analyze_pair(sdp, rtp)
        correlation = correlations(document, "MATCHED_ENDPOINT")[0]
        self.assertEqual(
            correlation["match_directions"], ["RTP_DESTINATION_ENDPOINT_MATCH"]
        )

    def test_03_ipv4_endpoint_match(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170)]
        )
        self.assertEqual(
            correlations(analyze_pair(sdp, rtp), "MATCHED_ENDPOINT")[0][
                "association_status"
            ],
            "MATCHED_ENDPOINT",
        )

    def test_04_ipv6_endpoint_match(self) -> None:
        body = (
            "v=0\r\n"
            "o=- 1000 1 IN IP6 2001:db8::10\r\n"
            "s=Synthetic\r\n"
            "c=IN IP6 2001:db8::10\r\n"
            "t=0 0\r\n"
            "m=audio 49172 RTP/AVP 0\r\n"
        )
        sdp = sdp_document(body)
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="2001:db8::20", destination="2001:db8::10", source_port=6000, destination_port=49172)]
        )
        document = analyze_pair(sdp, rtp)
        self.assertEqual(len(correlations(document, "MATCHED_ENDPOINT")), 1)

    def test_05_different_key_context_is_rejected(self) -> None:
        sdp = builder.sdp_analysis(KEY)
        rtp = builder.rtp_analysis(OTHER_KEY)
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, rtp)

    def test_06_different_capture_sha_is_rejected(self) -> None:
        sdp = builder.sdp_analysis()
        rtp = copy.deepcopy(builder.rtp_analysis())
        rtp["input_provenance"]["capture_sha256"] = "e5" * 32
        for event in rtp["events"]:
            event["capture_sha256"] = "e5" * 32
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, rtp)

    def test_07_different_capture_filename_is_rejected(self) -> None:
        sdp = builder.sdp_analysis()
        rtp = copy.deepcopy(builder.rtp_analysis())
        rtp["input_provenance"]["capture_files"] = ["other-capture.pcapng"]
        for event in rtp["events"]:
            event["capture_file"] = "other-capture.pcapng"
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, rtp)

    def test_08_same_endpoint_multiple_streams_is_ambiguous(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [
                stream_packet(1, stream=0, source="192.0.2.10", destination="192.0.2.20", source_port=49170, destination_port=6000),
                stream_packet(2, stream=1, source="192.0.2.10", destination="192.0.2.20", source_port=49170, destination_port=6002),
            ]
        )
        correlation = for_media(analyze_pair(sdp, rtp), 0)
        self.assertEqual(correlation["association_status"], "AMBIGUOUS")
        self.assertIn("MULTIPLE_RTP_STREAMS", correlation["conflict_findings"])
        self.assertEqual(correlation["correlation_strength"], "MEDIUM")

    def test_08b_bidirectional_mirror_pair_is_matched(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [
                stream_packet(1, stream=0, source="192.0.2.10", destination="192.0.2.20", source_port=49170, destination_port=6000),
                stream_packet(2, stream=1, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170),
            ]
        )
        correlation = for_media(analyze_pair(sdp, rtp), 0)
        self.assertEqual(correlation["association_status"], "MATCHED_ENDPOINT")
        self.assertEqual(correlation["correlation_strength"], "STRONG")
        self.assertEqual(len(correlation["rtp_udp_stream_references"]), 2)
        self.assertEqual(
            sorted(correlation["match_directions"]),
            ["RTP_DESTINATION_ENDPOINT_MATCH", "RTP_SOURCE_ENDPOINT_MATCH"],
        )

    def test_09_multiple_unrelated_sdp_sections_is_ambiguous(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        shared = next(
            item
            for item in document["correlations"]
            if item["association_status"] == "AMBIGUOUS"
        )
        self.assertEqual(len(shared["sdp_media_sections"]), 2)
        self.assertIn("UNRELATED_MEDIA_SHARE_ENDPOINT", shared["conflict_findings"])

    def test_10_valid_bundle_shared_transport(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        bundle = correlations(document, "BUNDLE_TRANSPORT_MATCHED")
        self.assertEqual(len(bundle), 1)
        self.assertEqual(len(bundle[0]["sdp_media_sections"]), 2)
        self.assertEqual(bundle[0]["match_directions"], ["RTP_DESTINATION_ENDPOINT_MATCH"])

    def test_11_unresolved_bundle_is_not_bundled(self) -> None:
        sdp = copy.deepcopy(builder.sdp_analysis())
        message = sdp["messages"][3]
        message["session"]["groups"][0]["reference_status"] = "UNRESOLVED"
        document = analyze_pair(sdp, builder.rtp_analysis())
        self.assertFalse(correlations(document, "BUNDLE_TRANSPORT_MATCHED"))
        self.assertTrue(correlations(document, "AMBIGUOUS"))

    def test_12_stream_endpoint_set_conflict_is_ambiguous(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [
                stream_packet(1, stream=0, source="192.0.2.10", destination="192.0.2.20", source_port=49170, destination_port=6000),
                stream_packet(2, stream=0, source="192.0.2.10", destination="198.51.100.50", source_port=49170, destination_port=7000, sequence=2),
            ]
        )
        correlation = for_media(analyze_pair(sdp, rtp), 0)
        self.assertEqual(correlation["association_status"], "AMBIGUOUS")
        self.assertIn("UDP_STREAM_ENDPOINT_SET_CONFLICT", correlation["conflict_findings"])

    def test_13_missing_endpoint_reference_is_insufficient(self) -> None:
        sdp = copy.deepcopy(basic_sdp())
        sdp["messages"][0]["media_sections"][0].pop("transport_endpoint", None)
        document = analyze_pair(sdp, empty_rtp_document())
        correlation = for_media(document, 0)
        self.assertEqual(correlation["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("ENDPOINT_REFERENCE_UNAVAILABLE", correlation["missing_evidence"])

    def test_14_missing_udp_stream_is_not_promoted(self) -> None:
        sdp = basic_sdp()
        record = stream_packet(1, stream=0, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170)
        record["fields"].pop("udp_stream")
        document = analyze_pair(sdp, rtp_document([record]))
        self.assertEqual(document["completeness"]["ungrouped_rtp_packet_count"], 1)
        self.assertEqual(for_media(document, 0)["association_status"], "UNMATCHED")

    def test_15_ice_endpoint_is_insufficient(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        ice = for_media(document, 1, ":3.1")
        self.assertEqual(ice["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn(
            "ICE_SELECTED_TRANSPORT_NOT_ESTABLISHED", ice["missing_evidence"]
        )

    def test_16_nat_translated_endpoint_is_unmatched(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="198.51.100.1", destination="198.51.100.2", source_port=40000, destination_port=40002)]
        )
        self.assertEqual(for_media(analyze_pair(sdp, rtp), 0)["association_status"], "UNMATCHED")

    def test_17_timestamp_similarity_never_creates_a_match(self) -> None:
        sdp = basic_sdp()
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="198.51.100.1", destination="198.51.100.2", source_port=40000, destination_port=40002)]
        )
        document = analyze_pair(sdp, rtp)
        self.assertEqual(for_media(document, 0)["association_status"], "UNMATCHED")


class CorrelationIntegrityTests(unittest.TestCase):
    def test_18_cross_capture_reference_is_rejected(self) -> None:
        sdp = builder.sdp_analysis()
        rtp = copy.deepcopy(builder.rtp_analysis())
        rtp["events"][0]["capture_file"] = "other.pcapng"
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, rtp)

    def test_19_duplicate_sdp_reference_is_rejected(self) -> None:
        sdp = copy.deepcopy(builder.sdp_analysis())
        sdp["messages"][1]["source_reference"] = sdp["messages"][0]["source_reference"]
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, builder.rtp_analysis())

    def test_20_duplicate_rtp_reference_is_rejected(self) -> None:
        rtp = copy.deepcopy(builder.rtp_analysis())
        rtp["events"][1]["event_reference"] = rtp["events"][0]["event_reference"]
        with self.assertRaises(model.InputError):
            analyze_pair(builder.sdp_analysis(), rtp)

    def test_21_invalid_media_index_is_rejected(self) -> None:
        sdp = copy.deepcopy(builder.sdp_analysis())
        sdp["messages"][0]["media_sections"][0]["index"] = -1
        with self.assertRaises(model.InputError):
            analyze_pair(sdp, builder.rtp_analysis())

    def test_21b_rtcp_event_without_parser_version_is_accepted(self) -> None:
        document = copy.deepcopy(builder.rtp_analysis())
        record = {
            "source_reference": f"rtcp-packet:{builder.CAPTURE}:900.1",
            "capture_file": builder.CAPTURE,
            "capture_sha256": builder.SHA,
            "frame_number": 900,
            "frame_timestamp": "1700000000.000900",
            "frame_reference": "frame:900",
            "message_occurrence": 1,
            "protocol": "RTCP",
            "fields": {},
        }
        component = {
            "packet_type": 200,
            "version": 2,
            "length": 6,
            "report_count": 0,
            "sender_ssrc": 0x12345678,
            "sender_report": {
                "ntp_msw": 1,
                "ntp_lsw": 2,
                "ntp_present": True,
                "rtp_timestamp": 3,
                "packet_count": 10,
                "octet_count": 1000,
            },
            "report_blocks": [],
            "udp_stream": 9,
        }
        event = builder.rtp_rtcp_model._rtcp_component(record, component, 0)
        self.assertNotIn("parser_version", event)
        document["events"].append(event)
        document["event_count"] += 1
        document["input_provenance"]["input_message_count"] += 1
        completeness = document["completeness"]
        completeness["rtcp_component_count"] += 1
        completeness["sr_component_count"] += 1
        completeness["observed_event_count"] += 1
        builder.rtp_rtcp_model.validate_analysis(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rtp-rtcp-with-rtcp.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = model.load_rtp_analysis(path)
        self.assertEqual(loaded["event_count"], document["event_count"])

    def test_22_incomplete_rtp_event_is_filtered(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        completeness = document["completeness"]
        self.assertEqual(completeness["non_observed_rtp_packet_count"], 1)
        self.assertNotIn(
            "rtp-udp-stream:synthetic-sdp-rtp-transport.pcapng:10",
            [
                item["rtp_udp_stream_reference"]
                for item in document["unmatched_streams"]
            ],
        )

    def test_23_unobserved_sdp_evidence_is_not_correlated(self) -> None:
        sdp = copy.deepcopy(basic_sdp())
        sdp["messages"][0]["evidence_status"] = "INCOMPLETE"
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170)]
        )
        correlation = for_media(analyze_pair(sdp, rtp), 0)
        self.assertEqual(correlation["association_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("SDP_EVIDENCE_NOT_OBSERVED", correlation["missing_evidence"])

    def test_24_count_conservation(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        completeness = document["completeness"]
        self.assertEqual(
            completeness["matched_correlation_count"]
            + completeness["bundle_matched_correlation_count"]
            + completeness["ambiguous_correlation_count"]
            + completeness["insufficient_correlation_count"]
            + completeness["unmatched_correlation_count"]
            + completeness["out_of_scope_correlation_count"],
            completeness["correlation_count"],
        )
        self.assertEqual(
            completeness["sdp_media_with_endpoint_count"]
            + completeness["sdp_media_without_endpoint_count"],
            completeness["sdp_media_section_count"],
        )
        self.assertEqual(
            completeness["rtp_stream_with_endpoint_count"]
            + completeness["rtp_stream_without_endpoint_count"],
            completeness["rtp_stream_count"],
        )

    def test_25_strict_schema_validation(self) -> None:
        if jsonschema is None:
            self.skipTest("jsonschema is unavailable")
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_26_privacy_has_no_raw_endpoints_or_key(self) -> None:
        document = analyze_pair(builder.sdp_analysis(), builder.rtp_analysis())
        text = json.dumps(document)
        for token in (
            "192.0.2.10",
            "192.0.2.20",
            "2001:db8::10",
            "49170",
            "source_address",
            "destination_address",
            "source_port",
            "destination_port",
            KEY.hex(),
        ):
            self.assertNotIn(token, text)

    def test_27_committed_example_expected_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "correlation.json"
        report = directory / "correlation.txt"
        completed = run_cli(INPUTS, output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            output.read_bytes(),
            (EXPECTED / "transport-correlation.json").read_bytes(),
        )
        self.assertEqual(
            report.read_bytes(),
            (EXPECTED / "transport-correlation.txt").read_bytes(),
        )

    def test_28_deterministic_replay_and_atomic_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        first = directory / "first.json"
        second = directory / "second.json"
        self.assertEqual(run_cli(INPUTS, first).returncode, 0)
        self.assertEqual(run_cli(INPUTS, second).returncode, 0)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_29_invalid_input_writes_no_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        sdp_path = directory / "sdp.json"
        rtp_path = directory / "rtp.json"
        sdp = builder.sdp_analysis()
        rtp = copy.deepcopy(builder.rtp_analysis())
        rtp["input_provenance"]["capture_sha256"] = "f6" * 32
        for event in rtp["events"]:
            event["capture_sha256"] = "f6" * 32
        _write(sdp_path, sdp)
        _write(rtp_path, rtp)
        output = directory / "out.json"
        completed = run_cli_paths(sdp_path, rtp_path, output)
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(output.exists())

    def test_30_output_collision_is_rejected(self) -> None:
        directory = Path(tempfile.mkdtemp())
        sdp_path = directory / "sdp.json"
        rtp_path = directory / "rtp.json"
        _write(sdp_path, builder.sdp_analysis())
        _write(rtp_path, builder.rtp_analysis())
        completed = run_cli_paths(sdp_path, rtp_path, sdp_path)
        self.assertNotEqual(completed.returncode, 0)

    def test_31_existing_protocol_expected_outputs_are_unchanged_without_key(self) -> None:
        protocol = SKILL.parents[1] / "protocol" / "sdp-rtp"
        sdp_expected = protocol / "examples" / "expected" / "sdp-analysis.json"
        rtp_expected = protocol / "examples" / "expected" / "rtp-rtcp-analysis.json"
        self.assertTrue(sdp_expected.is_file())
        self.assertTrue(rtp_expected.is_file())
        sdp = json.loads(sdp_expected.read_text(encoding="utf-8"))
        rtp = json.loads(rtp_expected.read_text(encoding="utf-8"))
        self.assertNotIn(
            "endpoint_context_reference", sdp["input_provenance"]
        )
        self.assertNotIn(
            "endpoint_context_reference", rtp["input_provenance"]
        )


    def test_35_multiple_sdp_messages_same_endpoint_are_ambiguous(self) -> None:
        body = (
            "v=0\r\n"
            "o=- 1000 1 IN IP4 192.0.2.10\r\n"
            "s=Synthetic\r\n"
            "c=IN IP4 192.0.2.10\r\n"
            "t=0 0\r\n"
            "m=audio 49170 RTP/AVP 0\r\n"
        )
        record = {
            "source_reference": f"sip-body:{builder.CAPTURE}:1.1",
            "capture_file": builder.CAPTURE,
            "capture_sha256": builder.SHA,
            "frame_number": 1,
            "frame_reference": "frame:1",
            "message_occurrence": 1,
            "sdp_body": body,
        }
        second = dict(record)
        second["source_reference"] = f"sip-body:{builder.CAPTURE}:2.1"
        second["frame_number"] = 2
        second["frame_reference"] = "frame:2"
        sdp = sdp_model.build_analysis([record, second], endpoint_key=KEY)
        rtp = rtp_document(
            [stream_packet(1, stream=0, source="192.0.2.20", destination="192.0.2.10", source_port=6000, destination_port=49170)]
        )
        document = analyze_pair(sdp, rtp)
        ambiguous = correlations(document, "AMBIGUOUS")
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(len(ambiguous[0]["sdp_message_references"]), 2)
        self.assertIn("UNRELATED_MEDIA_SHARE_ENDPOINT", ambiguous[0]["conflict_findings"])

    def test_36_no_endpoint_key_publishes_no_match(self) -> None:
        sdp = builder.sdp_analysis(None)
        rtp = builder.rtp_analysis(None)
        document = analyze_pair(sdp, rtp)
        self.assertEqual(document["correlation_count"], 11)
        self.assertFalse(correlations(document, "MATCHED_ENDPOINT"))
        self.assertFalse(correlations(document, "BUNDLE_TRANSPORT_MATCHED"))
        self.assertTrue(correlations(document, "INSUFFICIENT_EVIDENCE"))
        self.assertTrue(
            all(
                "ENDPOINT_REFERENCE_UNAVAILABLE" in item["missing_evidence"]
                for item in correlations(document, "INSUFFICIENT_EVIDENCE")
            )
        )


class EndpointKeyUtilityTests(unittest.TestCase):
    def test_32_key_generation_is_exclusive_owner_only_and_private(self) -> None:
        directory = Path(tempfile.mkdtemp())
        destination = directory / "endpoint.key"
        completed = subprocess.run(
            [sys.executable, str(KEY_CLI), "--output", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        material = destination.read_bytes()
        self.assertEqual(len(material), 32)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertNotIn(material.hex(), completed.stdout + completed.stderr)
        again = subprocess.run(
            [sys.executable, str(KEY_CLI), "--output", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(destination.read_bytes(), material)

    def test_33_key_generator_rejects_repository_path(self) -> None:
        repository = SKILL.parents[2]
        destination = repository / "forbidden-endpoint.key"
        self.assertFalse(destination.exists())
        completed = subprocess.run(
            [sys.executable, str(KEY_CLI), "--output", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(destination.exists())

    def test_34_protocol_cli_rejects_malformed_key_before_output(self) -> None:
        directory = Path(tempfile.mkdtemp())
        key = directory / "bad.key"
        key.write_bytes(b"short")
        os.chmod(key, 0o600)
        output = directory / "sdp.json"
        protocol = SKILL.parents[1] / "protocol" / "sdp-rtp"
        completed = subprocess.run(
            [
                sys.executable,
                str(protocol / "scripts" / "parse-sdp.py"),
                "--input",
                str(protocol / "examples" / "inputs" / "sdp-cases.jsonl"),
                "--output",
                str(output),
                "--endpoint-key-file",
                str(key),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertFalse(output.exists())


def run_cli(inputs: Path, output: Path, report: Path | None = None) -> subprocess.CompletedProcess:
    return run_cli_paths(
        inputs / "transport-sdp-analysis.json",
        inputs / "transport-rtp-rtcp-analysis.json",
        output,
        report,
    )


def run_cli_paths(
    sdp_path: Path,
    rtp_path: Path,
    output: Path,
    report: Path | None = None,
) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        str(CLI),
        "--sdp-analysis",
        str(sdp_path),
        "--rtp-rtcp-analysis",
        str(rtp_path),
        "--output",
        str(output),
        "--force",
    ]
    if report is not None:
        command.extend(["--report", str(report)])
    return subprocess.run(command, capture_output=True, text=True, check=False)