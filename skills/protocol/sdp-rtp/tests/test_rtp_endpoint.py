#!/usr/bin/env python3
"""Deterministic tests for optional RTP UDP endpoint references."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import endpoint_reference  # noqa: E402
import rtp_rtcp_fixture_builder as builder  # noqa: E402
import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402

KEY = hashlib.sha256(b"synthetic-rtp-endpoint-test-key").digest()


def analyze(records, key=KEY) -> dict:
    directory = Path(tempfile.mkdtemp())
    path = directory / "input.jsonl"
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    events, provenance = rtp_rtcp_model.extract_structured(path, endpoint_key=key)
    document = rtp_rtcp_model.build_analysis(events, provenance)
    rtp_rtcp_model.validate_analysis(document)
    return document


def one(record, key=KEY) -> dict:
    return analyze([record], key)["events"][0]


class RtpEndpointTests(unittest.TestCase):
    def test_01_ipv4_source_and_destination(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=5000,
                destination_port=6000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "ESTABLISHED")
        self.assertTrue(
            endpoint_reference.is_endpoint_reference(
                event["source_transport_endpoint_reference"]
            )
        )
        self.assertTrue(
            endpoint_reference.is_endpoint_reference(
                event["destination_transport_endpoint_reference"]
            )
        )

    def test_02_ipv6_source_and_destination(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="2001:db8::1",
                destination_address="2001:db8::2",
                source_port=5000,
                destination_port=6000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "ESTABLISHED")

    def test_03_structured_endpoint_fields_are_private_inputs(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=5000,
                destination_port=6000,
            )
        )
        text = json.dumps(event)
        self.assertNotIn("192.0.2.10", text)
        self.assertNotIn("192.0.2.20", text)
        self.assertNotIn('"source_port"', text)
        self.assertNotIn("5000", text)

    def test_04_missing_source_address_is_incomplete(self) -> None:
        event = one(
            builder.rtp(
                1,
                destination_address="192.0.2.20",
                source_port=5000,
                destination_port=6000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "INCOMPLETE")
        self.assertIn(
            "UDP_ENDPOINT_FIELDS_INCOMPLETE", event["transport_endpoint_reason_codes"]
        )

    def test_05_missing_destination_address_is_incomplete(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                source_port=5000,
                destination_port=6000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "INCOMPLETE")

    def test_06_missing_port_is_incomplete(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=5000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "INCOMPLETE")

    def test_07_all_endpoint_fields_missing_are_unavailable(self) -> None:
        event = one(builder.rtp(1))
        self.assertEqual(event["transport_endpoint_status"], "UNAVAILABLE")
        self.assertIn(
            "UDP_ENDPOINT_FIELDS_UNAVAILABLE",
            event["transport_endpoint_reason_codes"],
        )

    def test_08_invalid_address_is_rejected_at_load(self) -> None:
        record = builder.rtp(
            1,
            source_address="not-an-ip",
            destination_address="192.0.2.20",
            source_port=5000,
            destination_port=6000,
        )
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(rtp_rtcp_model.InputError):
            rtp_rtcp_model.load_structured_messages(path)

    def test_09_port_zero_is_not_a_valid_endpoint(self) -> None:
        event = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=0,
                destination_port=6000,
            )
        )
        self.assertEqual(event["transport_endpoint_status"], "UNAVAILABLE")
        self.assertIn("UDP_ENDPOINT_INVALID", event["transport_endpoint_reason_codes"])

    def test_10_different_ports_produce_different_references(self) -> None:
        first = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=5000,
                destination_port=6000,
            )
        )
        second = one(
            builder.rtp(
                1,
                source_address="192.0.2.10",
                destination_address="192.0.2.20",
                source_port=5002,
                destination_port=6000,
            )
        )
        self.assertNotEqual(
            first["source_transport_endpoint_reference"],
            second["source_transport_endpoint_reference"],
        )

    def test_11_missing_udp_stream_keeps_endpoint_but_no_stream(self) -> None:
        record = builder.rtp(
            1,
            source_address="192.0.2.10",
            destination_address="192.0.2.20",
            source_port=5000,
            destination_port=6000,
        )
        record["fields"].pop("udp_stream")
        event = one(record)
        self.assertIsNone(event["udp_stream"])
        self.assertEqual(event["transport_endpoint_status"], "ESTABLISHED")

    def test_12_rtcp_is_not_promoted_to_rtp_endpoint_evidence(self) -> None:
        document = analyze([builder.rtcp(1, [builder.sender_report()])])
        event = document["events"][0]
        self.assertEqual(event["protocol"], "RTCP")
        self.assertNotIn("transport_endpoint_status", event)

    def test_13_no_key_preserves_previous_rtp_output(self) -> None:
        document = analyze([builder.rtp(1)], key=None)
        event = document["events"][0]
        for field in (
            "source_transport_endpoint_reference",
            "destination_transport_endpoint_reference",
            "transport_endpoint_status",
            "transport_endpoint_reason_codes",
        ):
            self.assertNotIn(field, event)
        self.assertNotIn(
            "endpoint_context_reference", document["input_provenance"]
        )

    def test_14_context_matches_sdp_for_same_key_and_capture(self) -> None:
        document = analyze([builder.rtp(1)])
        sdp_context = endpoint_reference.endpoint_context_reference(
            KEY, builder.SHA
        )
        self.assertEqual(
            document["input_provenance"]["endpoint_context_reference"], sdp_context
        )
        sdp_document = sdp_model.build_analysis(
            [
                {
                    "source_reference": f"sip-body:{builder.CAPTURE}:1.1",
                    "capture_file": builder.CAPTURE,
                    "capture_sha256": builder.SHA,
                    "frame_number": 1,
                    "frame_reference": "frame:1",
                    "message_occurrence": 1,
                    "sdp_body": "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=x\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\n",
                }
            ],
            endpoint_key=KEY,
        )
        self.assertEqual(
            sdp_document["input_provenance"]["endpoint_context_reference"],
            document["input_provenance"]["endpoint_context_reference"],
        )

    def _capture_event(self, layers: dict) -> dict:
        capture = Path(tempfile.mkdtemp()) / "capture.pcap"
        capture.write_bytes(b"capture")

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
                                **layers,
                            }
                        }
                    }
                ]
            }

        events, _provenance = rtp_rtcp_model.extract_capture(
            capture, prober=lambda _tshark: None, runner=runner, endpoint_key=KEY
        )
        return events[0]

    def _rtp_layer(self) -> dict:
        return {
            "rtp.version": "2",
            "rtp.padding": "0",
            "rtp.ext": "0",
            "rtp.cc": "0",
            "rtp.marker": "0",
            "rtp.p_type": "0",
            "rtp.seq": "1",
            "rtp.timestamp": "160",
            "rtp.ssrc": "0x01020304",
        }

    def test_15_tshark_ipv4_endpoint_extraction(self) -> None:
        event = self._capture_event(
            {
                "ip": {"ip.src": "192.0.2.10", "ip.dst": "192.0.2.20"},
                "udp": {
                    "udp.stream": "0",
                    "udp.stream.pnum": "1",
                    "udp.srcport": "5000",
                    "udp.dstport": "6000",
                },
                "rtp": self._rtp_layer(),
            }
        )
        self.assertEqual(event["transport_endpoint_status"], "ESTABLISHED")

    def test_16_tshark_ipv6_endpoint_extraction(self) -> None:
        event = self._capture_event(
            {
                "ipv6": {"ipv6.src": "2001:db8::1", "ipv6.dst": "2001:db8::2"},
                "udp": {
                    "udp.stream": "0",
                    "udp.stream.pnum": "1",
                    "udp.srcport": "5000",
                    "udp.dstport": "6000",
                },
                "rtp": self._rtp_layer(),
            }
        )
        self.assertEqual(event["transport_endpoint_status"], "ESTABLISHED")

    def test_17_tshark_encapsulation_is_ambiguous(self) -> None:
        event = self._capture_event(
            {
                "ip": {"ip.src": "192.0.2.10", "ip.dst": "192.0.2.20"},
                "udp": {
                    "udp.stream": "0",
                    "udp.stream.pnum": "1",
                    "udp.srcport": "2152",
                    "udp.dstport": "2152",
                },
                "gtp": {"gtp.teid": "1"},
                "rtp": self._rtp_layer(),
            }
        )
        self.assertEqual(event["transport_endpoint_status"], "AMBIGUOUS")
        self.assertIn(
            "MULTIPLE_TRANSPORT_CANDIDATES", event["transport_endpoint_reason_codes"]
        )

    def test_18_tshark_multiple_ip_layers_are_ambiguous(self) -> None:
        event = self._capture_event(
            {
                "ip": [
                    {"ip.src": "192.0.2.10", "ip.dst": "192.0.2.20"},
                    {"ip.src": "198.51.100.1", "ip.dst": "198.51.100.2"},
                ],
                "udp": {
                    "udp.stream": "0",
                    "udp.stream.pnum": "1",
                    "udp.srcport": "5000",
                    "udp.dstport": "6000",
                },
                "rtp": self._rtp_layer(),
            }
        )
        self.assertEqual(event["transport_endpoint_status"], "AMBIGUOUS")
    def test_19_tshark_missing_source_address_is_incomplete(self) -> None:
        event = self._capture_event(
            {
                "ip": {"ip.dst": "192.0.2.20"},
                "udp": {
                    "udp.stream": "0",
                    "udp.stream.pnum": "1",
                    "udp.srcport": "5000",
                    "udp.dstport": "6000",
                },
                "rtp": self._rtp_layer(),
            }
        )
        self.assertEqual(event["transport_endpoint_status"], "INCOMPLETE")
        self.assertIn(
            "UDP_ENDPOINT_FIELDS_INCOMPLETE", event["transport_endpoint_reason_codes"]
        )
