#!/usr/bin/env python3
"""Capture-scope integrity tests for SIP identity references."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "skills" / "protocol" / "sip" / "scripts"))
import sip_model  # noqa: E402

KEY = b"k" * 32
SHA_A = "a" * 64
SHA_B = "b" * 64
RAW_CALL_ID = "raw-call-id-value"
RAW_FROM_TAG = "raw-from-tag"
RAW_VIA_BRANCH = "z9hG4bK-raw-branch"


def record(capture: str = "same-name.pcapng") -> dict:
    return {
        "capture_file": capture,
        "frame_number": 1,
        "frame_time_epoch": "1700000200.000000001",
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
            "call_id": RAW_CALL_ID,
            "cseq_sequence": 1,
            "cseq_method": "INVITE",
            "via": [
                {
                    "branch": RAW_VIA_BRANCH,
                    "sent_by": "192.0.2.10:5060",
                    "transport": "UDP",
                }
            ],
            "from": {"uri": "sip:alice@example.com", "count": 1, "tag": RAW_FROM_TAG},
            "to": {"uri": "sip:bob@example.com", "count": 1, "tag": None},
            "content_length": 0,
            "body_length": 0,
            "request_uri": "sip:bob@example.com",
            "method": "INVITE",
            "max_forwards": 70,
        },
    }


def event(capture_scope: str | None, *, identity_key: bytes | None = KEY, capture: str = "same-name.pcapng") -> dict:
    return sip_model.normalize_record_message(
        record(capture),
        identity_key=identity_key,
        capture_scope=capture_scope,
    )["event"]


class CaptureScopeTests(unittest.TestCase):
    def test_same_filename_with_different_capture_sha_never_shares_identity(self) -> None:
        first = event(SHA_A)
        second = event(SHA_B)
        self.assertNotEqual(
            first["call_id_reference"], second["call_id_reference"]
        )
        self.assertNotEqual(
            first["from_tag_reference"], second["from_tag_reference"]
        )
        self.assertNotEqual(
            first["via_branch_references"], second["via_branch_references"]
        )

    def test_same_capture_sha_is_deterministic(self) -> None:
        first = event(SHA_A)
        second = event(SHA_A)
        self.assertEqual(first, second)

    def test_scope_status_requires_capture_sha(self) -> None:
        self.assertEqual(
            event(SHA_A)["identity_reference_scope"],
            "CAPTURE_SHA256_SCOPED_HMAC_SHA256",
        )
        self.assertEqual(
            event(None)["identity_reference_scope"],
            "CAPTURE_BASENAME_SCOPED_HMAC_SHA256",
        )
        self.assertIsNone(event(SHA_A, identity_key=None)["identity_reference_scope"])

    def test_invalid_capture_scope_falls_back_to_basename(self) -> None:
        first = event("not-a-sha")
        second = event(None)
        self.assertEqual(first["call_id_reference"], second["call_id_reference"])
        self.assertEqual(
            first["identity_reference_scope"],
            "CAPTURE_BASENAME_SCOPED_HMAC_SHA256",
        )

    def test_missing_key_never_publishes_identity(self) -> None:
        document = event(SHA_A, identity_key=None)
        self.assertEqual(document["identity_reference_status"], "UNAVAILABLE_NO_KEY")
        self.assertIsNone(document["call_id_reference"])
        self.assertIsNone(document["from_tag_reference"])
        self.assertEqual(document["via_branch_references"], [])

    def test_raw_identity_values_and_key_are_never_published(self) -> None:
        text = json.dumps(event(SHA_A))
        for token in (RAW_CALL_ID, RAW_FROM_TAG, RAW_VIA_BRANCH, KEY.hex()):
            self.assertNotIn(token, text)

    def test_different_capture_files_with_same_sha_stay_separate(self) -> None:
        first = event(SHA_A, capture="capture-one.pcapng")
        second = event(SHA_A, capture="capture-two.pcapng")
        self.assertNotEqual(
            first["call_id_reference"], second["call_id_reference"]
        )


if __name__ == "__main__":
    unittest.main()