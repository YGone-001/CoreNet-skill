#!/usr/bin/env python3
"""Deterministic cross-platform JSON semantic hashing.

Provides canonical serialization and SHA-256 computation that is invariant to
newline representations (LF vs CRLF), key order, and formatting whitespace.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(document: Any) -> bytes:
    """Serialize a document into canonical, deterministic UTF-8 JSON bytes."""
    if isinstance(document, (str, bytes)):
        document = json.loads(document)
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_json_sha256(document: Any) -> str:
    """Compute the deterministic cross-platform SHA-256 digest of a JSON document."""
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()
