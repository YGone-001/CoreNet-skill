#!/usr/bin/env python3
"""Deterministic tests for capture-scoped HMAC endpoint references."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import endpoint_reference  # noqa: E402

KEY = hashlib.sha256(b"synthetic-endpoint-reference-test-key").digest()
SHA_A = "a1" * 32
SHA_B = "b2" * 32


class EndpointReferenceTests(unittest.TestCase):
    def test_01_same_key_capture_endpoint_is_deterministic(self) -> None:
        first = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        second = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        self.assertEqual(first, second)
        self.assertTrue(endpoint_reference.is_endpoint_reference(first))

    def test_02_different_key_changes_reference(self) -> None:
        first = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        second = endpoint_reference.endpoint_reference(bytes(reversed(KEY)), SHA_A, "192.0.2.10", 49170)
        self.assertNotEqual(first, second)

    def test_03_different_capture_changes_reference(self) -> None:
        first = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        second = endpoint_reference.endpoint_reference(KEY, SHA_B, "192.0.2.10", 49170)
        self.assertNotEqual(first, second)

    def test_04_ipv4_endpoint(self) -> None:
        value = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        self.assertRegex(value, r"^endpoint-hmac-sha256:v1:[0-9a-f]{64}$")

    def test_05_ipv6_endpoint(self) -> None:
        value = endpoint_reference.endpoint_reference(KEY, SHA_A, "2001:db8::10", 49170)
        self.assertRegex(value, r"^endpoint-hmac-sha256:v1:[0-9a-f]{64}$")

    def test_06_address_family_changes_reference(self) -> None:
        ipv4 = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        ipv6 = endpoint_reference.endpoint_reference(KEY, SHA_A, "2001:db8::10", 49170)
        self.assertNotEqual(ipv4, ipv6)

    def test_07_different_ip_changes_reference(self) -> None:
        first = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        second = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.11", 49170)
        self.assertNotEqual(first, second)

    def test_08_different_port_changes_reference(self) -> None:
        first = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        second = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49171)
        self.assertNotEqual(first, second)

    def test_09_invalid_ip_and_port_are_rejected(self) -> None:
        for address, port in (
            ("not-an-ip", 49170),
            ("192.0.2.10", 0),
            ("192.0.2.10", 65536),
            ("192.0.2.10", "49170"),
        ):
            with self.subTest(address=address, port=port):
                with self.assertRaises(endpoint_reference.EndpointError):
                    endpoint_reference.endpoint_reference(KEY, SHA_A, address, port)

    def test_10_context_is_capture_scoped_and_keyed(self) -> None:
        same = endpoint_reference.endpoint_context_reference(KEY, SHA_A)
        self.assertEqual(same, endpoint_reference.endpoint_context_reference(KEY, SHA_A))
        self.assertTrue(endpoint_reference.is_context_reference(same))
        self.assertNotEqual(same, endpoint_reference.endpoint_context_reference(bytes(reversed(KEY)), SHA_A))
        self.assertNotEqual(same, endpoint_reference.endpoint_context_reference(KEY, SHA_B))
        self.assertNotEqual(same, endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170))

    def test_11_reference_is_not_an_unkeyed_hash(self) -> None:
        value = endpoint_reference.endpoint_reference(KEY, SHA_A, "192.0.2.10", 49170)
        digest = value.rsplit(":", 1)[1]
        payload = (
            b"UDP" + b"192.0.2.10" + b"49170" + SHA_A.encode("ascii")
        )
        self.assertNotEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertNotIn("192.0.2.10", value)
        self.assertNotIn("49170", value)

    def test_12_key_loading_enforces_size_and_owner_only_mode(self) -> None:
        directory = Path(tempfile.mkdtemp())
        good = directory / "good.key"
        good.write_bytes(KEY)
        os.chmod(good, 0o600)
        self.assertEqual(endpoint_reference.load_endpoint_key(good), KEY)
        bad_size = directory / "short.key"
        bad_size.write_bytes(b"short")
        os.chmod(bad_size, 0o600)
        with self.assertRaises(endpoint_reference.EndpointKeyError):
            endpoint_reference.load_endpoint_key(bad_size)
        with self.assertRaises(endpoint_reference.EndpointKeyError):
            endpoint_reference.load_endpoint_key(directory / "missing.key")
        if os.name == "posix":
            loose = directory / "loose.key"
            loose.write_bytes(KEY)
            os.chmod(loose, 0o644)
            with self.assertRaises(endpoint_reference.EndpointKeyError):
                endpoint_reference.load_endpoint_key(loose)
            self.assertEqual(stat.S_IMODE(loose.stat().st_mode), 0o644)