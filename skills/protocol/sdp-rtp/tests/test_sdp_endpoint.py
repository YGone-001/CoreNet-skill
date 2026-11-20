#!/usr/bin/env python3
"""Deterministic tests for optional SDP media endpoint references."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import endpoint_reference  # noqa: E402
import sdp_model  # noqa: E402

KEY = hashlib.sha256(b"synthetic-sdp-endpoint-test-key").digest()
CAPTURE = "synthetic-sdp-endpoint.pcapng"
SHA = "d4" * 32


def body(lines: list[str]) -> str:
    return "\r\n".join(lines) + "\r\n"


def record(value: str, index: int = 1) -> dict:
    return {
        "source_reference": f"sip-body:{CAPTURE}:{index}.1",
        "capture_file": CAPTURE,
        "capture_sha256": SHA,
        "frame_number": index,
        "frame_reference": f"frame:{index}",
        "message_occurrence": 1,
        "sdp_body": value,
    }


def analyze(value: str, *, key: bytes | None = KEY) -> dict:
    return sdp_model.build_analysis([record(value)], endpoint_key=key)


def media(document: dict, index: int = 0) -> dict:
    return document["messages"][0]["media_sections"][index]


def endpoint(document: dict, index: int = 0) -> dict:
    return media(document, index)["transport_endpoint"]


def base(extra: list[str], connection: str = "c=IN IP4 192.0.2.10") -> str:
    return body(
        ["v=0", "o=- 1000 1 IN IP4 192.0.2.10", "s=Synthetic", connection, "t=0 0", *extra]
    )


class SdpEndpointTests(unittest.TestCase):
    def test_01_session_connection_inheritance(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/AVP 0"]))
        self.assertEqual(endpoint(item)["endpoint_status"], "ESTABLISHED")
        self.assertEqual(endpoint(item)["transport"], "UDP")

    def test_02_media_connection_override(self) -> None:
        value = body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.10",
                "s=Synthetic",
                "c=IN IP4 192.0.2.10",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
                "c=IN IP6 2001:db8::10",
            ]
        )
        item = analyze(value)
        self.assertEqual(endpoint(item)["address_family"], "IPv6")

    def test_03_ipv4_endpoint(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/AVP 0"]))
        self.assertEqual(endpoint(item)["address_family"], "IPv4")

    def test_04_ipv6_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 49170 RTP/AVP 0"], connection="c=IN IP6 2001:db8::10")
        )
        self.assertEqual(endpoint(item)["address_family"], "IPv6")

    def test_05_disabled_media_has_no_endpoint(self) -> None:
        item = analyze(base(["m=audio 0 RTP/AVP 0"]))
        self.assertEqual(endpoint(item)["endpoint_status"], "OUT_OF_SCOPE")
        self.assertIn("MEDIA_DISABLED", endpoint(item)["reason_codes"])
        self.assertIsNone(endpoint(item)["endpoint_reference"])

    def test_06_multicast_has_no_endpoint(self) -> None:
        item = analyze(
            base(
                ["m=audio 49170 RTP/AVP 0", "c=IN IP4 239.1.1.1/127"],
            )
        )
        self.assertEqual(endpoint(item)["endpoint_status"], "OUT_OF_SCOPE")
        self.assertIn("MULTICAST_ADDRESS_UNSUPPORTED", endpoint(item)["reason_codes"])

    def test_07_unspecified_address_has_no_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 49170 RTP/AVP 0"], connection="c=IN IP4 0.0.0.0")
        )
        self.assertIn("UNSPECIFIED_ADDRESS_UNSUPPORTED", endpoint(item)["reason_codes"])

    def test_08_link_local_address_has_no_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 49170 RTP/AVP 0"], connection="c=IN IP4 169.254.1.1")
        )
        self.assertIn("LINK_LOCAL_ADDRESS_UNSUPPORTED", endpoint(item)["reason_codes"])

    def test_09_domain_name_has_no_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 49170 RTP/AVP 0"], connection="c=IN IP4 media.example.com")
        )
        self.assertIn("DOMAIN_NAME_UNRESOLVED", endpoint(item)["reason_codes"])

    def test_10_invalid_connection_has_no_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 49170 RTP/AVP 0"], connection="c=IN IP4 999.1.1.1")
        )
        self.assertIsNone(endpoint(item)["endpoint_reference"])

    def test_11_multiple_connection_lines_are_ambiguous(self) -> None:
        value = body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.10",
                "s=Synthetic",
                "c=IN IP4 192.0.2.10",
                "c=IN IP4 192.0.2.11",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
            ]
        )
        item = analyze(value)
        self.assertEqual(endpoint(item)["endpoint_status"], "UNAVAILABLE")
        self.assertIn("AMBIGUOUS_CONNECTION", endpoint(item)["reason_codes"])

    def test_12_unsupported_transport_has_no_endpoint(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/SAVP 0"]))
        self.assertEqual(endpoint(item)["endpoint_status"], "OUT_OF_SCOPE")
        self.assertIn("UNSUPPORTED_TRANSPORT_PROTOCOL", endpoint(item)["reason_codes"])

    def test_13_multiple_port_count_has_no_endpoint(self) -> None:
        item = analyze(base(["m=audio 49170/2 RTP/AVP 0"]))
        self.assertIn("UNSUPPORTED_PORT_COUNT", endpoint(item)["reason_codes"])

    def test_14_rtcp_port_does_not_replace_rtp_port(self) -> None:
        item = analyze(
            base(
                [
                    "m=audio 49170 RTP/AVP 0",
                    "a=rtcp:49171 IN IP4 192.0.2.99",
                ]
            )
        )
        reference = endpoint(item)["endpoint_reference"]
        expected = endpoint_reference.endpoint_reference(
            KEY, SHA, "192.0.2.10", 49170
        )
        rtcp_reference = endpoint_reference.endpoint_reference(
            KEY, SHA, "192.0.2.99", 49171
        )
        self.assertEqual(reference, expected)
        self.assertNotEqual(reference, rtcp_reference)

    def test_15_rtcp_mux_does_not_alter_rtp_endpoint(self) -> None:
        plain = analyze(base(["m=audio 49170 RTP/AVP 0"]))
        muxed = analyze(base(["m=audio 49170 RTP/AVP 0", "a=rtcp-mux"]))
        self.assertEqual(
            endpoint(plain)["endpoint_reference"],
            endpoint(muxed)["endpoint_reference"],
        )

    def test_16_ice_candidate_makes_endpoint_unavailable(self) -> None:
        item = analyze(
            base(
                [
                    "m=audio 49170 RTP/AVP 0",
                    "a=candidate:1 1 udp 2122260223 192.0.2.10 49170 typ host",
                ]
            )
        )
        self.assertEqual(endpoint(item)["endpoint_status"], "UNAVAILABLE")
        self.assertIn(
            "ICE_SELECTED_TRANSPORT_NOT_ESTABLISHED", endpoint(item)["reason_codes"]
        )

    def test_17_ice_credentials_make_endpoint_unavailable(self) -> None:
        item = analyze(
            base(
                [
                    "a=ice-ufrag:private-ufrag",
                    "a=ice-pwd:private-password",
                    "m=audio 49170 RTP/AVP 0",
                ]
            )
        )
        self.assertEqual(endpoint(item)["endpoint_status"], "UNAVAILABLE")

    def test_18_unresolved_bundle_does_not_remove_direct_endpoint(self) -> None:
        value = body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.10",
                "s=Synthetic",
                "c=IN IP4 192.0.2.10",
                "t=0 0",
                "a=group:BUNDLE 0 9",
                "m=audio 49170 RTP/AVP 0",
                "a=mid:0",
            ]
        )
        item = analyze(value)
        self.assertEqual(item["messages"][0]["session"]["groups"][0]["reference_status"], "UNRESOLVED")
        self.assertEqual(endpoint(item)["endpoint_status"], "ESTABLISHED")

    def test_19_bundle_only_disabled_media_has_no_endpoint(self) -> None:
        item = analyze(
            base(["m=audio 0 RTP/AVP 0", "a=mid:0", "a=bundle-only"])
        )
        self.assertEqual(endpoint(item)["endpoint_status"], "OUT_OF_SCOPE")
        self.assertIn("MEDIA_DISABLED", endpoint(item)["reason_codes"])

    def test_20_valid_bundle_shared_transport(self) -> None:
        value = body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.30",
                "s=Synthetic",
                "c=IN IP4 192.0.2.30",
                "t=0 0",
                "a=group:BUNDLE 0 1",
                "m=audio 5000 RTP/AVP 0",
                "a=mid:0",
                "m=video 5000 RTP/AVP 96",
                "a=mid:1",
                "a=rtpmap:96 H264/90000",
            ]
        )
        item = analyze(value)
        self.assertEqual(
            endpoint(item, 0)["endpoint_reference"],
            endpoint(item, 1)["endpoint_reference"],
        )
        self.assertEqual(item["messages"][0]["session"]["groups"][0]["reference_status"], "RESOLVED")

    def test_21_duplicate_mid_is_ambiguous(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/AVP 0", "a=mid:0", "a=mid:1"]))
        self.assertEqual(media(item)["mid"], "AMBIGUOUS")

    def test_22_missing_mid_is_preserved(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/AVP 0"]))
        self.assertIsNone(media(item)["mid"])
        self.assertEqual(endpoint(item)["endpoint_status"], "ESTABLISHED")

    def test_23_no_key_preserves_previous_output(self) -> None:
        item = analyze(base(["m=audio 49170 RTP/AVP 0"]), key=None)
        self.assertNotIn("transport_endpoint", media(item))
        provenance = item["input_provenance"]
        self.assertNotIn("endpoint_context_reference", provenance)
        text = str(item)
        self.assertNotIn("192.0.2.10", text)
        self.assertNotIn("_raw_address", text)

    def test_24_schema_validation_with_endpoints(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is unavailable")
        import json

        document = analyze(base(["m=audio 49170 RTP/AVP 0"]))
        schema = json.loads(
            (SKILL / "schemas" / "sdp-events.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.validate(document, schema)
        sdp_model.validate_analysis(document)