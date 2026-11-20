#!/usr/bin/env python3
"""Privacy-safe capture-scoped endpoint references for SDP and RTP evidence.

This helper turns a UDP transport endpoint into a keyed, opaque reference. It
never publishes, logs or returns the raw address or port. The HMAC key is
supplied by an explicit local key file; no key is generated or embedded here.

The construction is versioned and domain-separated:

    HMAC-SHA256(key, "corenet-sdp-rtp-endpoint:v1" || 0x00 || payload)
    payload = transport_code(1) || address_family(1) ||
              capture_sha256(32) || packed_address(4|16) || port(2, big-endian)

A separate domain yields a capture-scoped correlation context reference:

    HMAC-SHA256(key, "corenet-sdp-rtp-context:v1" || 0x00 ||
                context_version(1) || capture_sha256(32))
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Any

KEY_SIZE = 32
ENDPOINT_DOMAIN = b"corenet-sdp-rtp-endpoint:v1"
CONTEXT_DOMAIN = b"corenet-sdp-rtp-context:v1"
ENDPOINT_PREFIX = "endpoint-hmac-sha256:v1:"
CONTEXT_PREFIX = "endpoint-context-hmac-sha256:v1:"
DOMAIN_SEPARATOR = b"\x00"
CONTEXT_VERSION = 1
TRANSPORT_CODES = {"UDP": 1}
CAPTURE_SHA_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ENDPOINT_REFERENCE_PATTERN = re.compile(
    r"^endpoint-hmac-sha256:v1:[0-9a-f]{64}$"
)
CONTEXT_REFERENCE_PATTERN = re.compile(
    r"^endpoint-context-hmac-sha256:v1:[0-9a-f]{64}$"
)


class EndpointKeyError(ValueError):
    """Raised when a local endpoint key file is missing or unusable."""


class EndpointError(ValueError):
    """Raised when an endpoint cannot be represented unambiguously."""


def _capture_bytes(capture_sha256: str) -> bytes:
    if not isinstance(capture_sha256, str) or not CAPTURE_SHA_PATTERN.fullmatch(
        capture_sha256
    ):
        raise EndpointError("capture SHA-256 must be lowercase hexadecimal")
    return bytes.fromhex(capture_sha256)


def _address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if not isinstance(value, str):
        raise EndpointError("endpoint address must be a string")
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise EndpointError("endpoint address is not a valid IP address") from None


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise EndpointError("endpoint port must be within 1..65535")
    return value


def _transport_code(transport: Any) -> int:
    if not isinstance(transport, str) or transport not in TRANSPORT_CODES:
        raise EndpointError("only UDP transport endpoints are supported")
    return TRANSPORT_CODES[transport]


def endpoint_reference(
    key: bytes,
    capture_sha256: str,
    address: Any,
    port: int,
    transport: str = "UDP",
) -> str:
    """Return the capture-scoped HMAC endpoint reference."""
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise EndpointKeyError("endpoint key must be exactly 32 bytes")
    parsed_address = _address(address)
    payload = (
        bytes([_transport_code(transport)])
        + bytes([parsed_address.version])
        + _capture_bytes(capture_sha256)
        + parsed_address.packed
        + _port(port).to_bytes(2, "big")
    )
    digest = hmac.new(
        key, ENDPOINT_DOMAIN + DOMAIN_SEPARATOR + payload, hashlib.sha256
    ).hexdigest()
    return ENDPOINT_PREFIX + digest


def endpoint_context_reference(key: bytes, capture_sha256: str) -> str:
    """Return the capture-scoped HMAC correlation context reference."""
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise EndpointKeyError("endpoint key must be exactly 32 bytes")
    payload = bytes([CONTEXT_VERSION]) + _capture_bytes(capture_sha256)
    digest = hmac.new(
        key, CONTEXT_DOMAIN + DOMAIN_SEPARATOR + payload, hashlib.sha256
    ).hexdigest()
    return CONTEXT_PREFIX + digest


def is_endpoint_reference(value: Any) -> bool:
    return isinstance(value, str) and ENDPOINT_REFERENCE_PATTERN.fullmatch(value) is not None


def is_context_reference(value: Any) -> bool:
    return isinstance(value, str) and CONTEXT_REFERENCE_PATTERN.fullmatch(value) is not None


def load_endpoint_key(path: Path) -> bytes:
    """Read a 32-byte owner-only local key file without publishing its content."""
    try:
        file_stat = path.stat()
    except OSError:
        raise EndpointKeyError("endpoint key file is missing or unreadable") from None
    if not stat.S_ISREG(file_stat.st_mode):
        raise EndpointKeyError("endpoint key path is not a regular file")
    if os.name == "posix" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise EndpointKeyError("endpoint key file must be owner-only (0600)")
    try:
        material = path.read_bytes()
    except OSError:
        raise EndpointKeyError("endpoint key file is missing or unreadable") from None
    if len(material) != KEY_SIZE:
        raise EndpointKeyError("endpoint key file must contain exactly 32 bytes")
    return material