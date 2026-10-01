#!/usr/bin/env python3
"""Shared, standalone helpers for cross-protocol evidence correlation.

This layer combines already-extracted protocol events (NGAP detailed
events from skills/protocol/ngap and NAS-5GS detailed events from
skills/protocol/nas-5gs) into deterministic correlation groups and a
unified evidence timeline. It parses no PCAP, no NAS, and no NGAP: the
protocol Skills remain authoritative for their own semantics.

Correlation keys, in evidence order:
- STRONG: events sharing capture_file and frame_number (at least two
  events joined on the same frame).
- MEDIUM: events in one capture whose adjacent timestamps lie within a
  bounded window (chained pairs only; each adjacent pair is within the
  window, which is documented and deterministic).
- WEAK: a single event with only capture context; it is never merged
  with anything automatically and forms its own partial-timeline group.

The layer never creates subscriber, session, or registration
correlation, never interprets foreign protocol identifiers, and never
produces success, failure, or root-cause verdicts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

STRONG = "STRONG"
MEDIUM = "MEDIUM"
WEAK = "WEAK"

NGAP = "NGAP"
NAS = "NAS-5GS"
KNOWN_PROTOCOLS = (NGAP, NAS)

DEFAULT_WINDOW_SECONDS = 1.0
MAX_WINDOW_SECONDS = 3600.0

# Fields whose presence marks an event as carrying sensitive material.
# Values matter more than names, but any such key in an input event is
# treated as a policy violation because this layer must stay free of
# subscriber identity and authentication secret material.
SENSITIVE_KEYS = (
    "imsi", "supi", "suci", "msisdn", "guti", "fiveg_guti",
    "rand", "autn", "res", "auts", "kseaf", "kamf",
    "rand_value", "autn_value", "res_value", "auts_value",
    "identity_value",
)
SENSITIVE_BYTES_FIELDS = ("nas_payload", "nas_pdu_value", "authentication_vector")

# NGAP UE-context identifiers are foreign protocol metadata: preserved
# verbatim if present, never parsed, renamed, or interpreted.
FOREIGN_METADATA_ALLOWED = ("amf_ue_ngap_id", "ran_ue_ngap_id")

EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7


class InputError(ValueError):
    """Raised when an input event cannot be used for correlation."""


def load_event(record: object, source: str, index: int) -> dict[str, object]:
    """Validate one input event and attach its source protocol label.

    Events are foreign evidence: shape validation checks only the
    provenance fields this layer joins on, plus the sensitive-data
    policy. Protocol semantics are never interpreted here.
    """
    if source not in KNOWN_PROTOCOLS:
        raise InputError(f"unknown source protocol: {source}")
    if not isinstance(record, dict):
        raise InputError(f"{source} event {index} is not a JSON object")
    for key in ("timestamp", "frame_number", "capture_file"):
        if key not in record:
            raise InputError(f"{source} event {index} lacks required provenance field: {key}")
    frame_number = record["frame_number"]
    if not isinstance(frame_number, int) or isinstance(frame_number, bool) or frame_number < 1:
        raise InputError(f"{source} event {index} frame_number must be a positive integer")
    capture_file = record["capture_file"]
    if not isinstance(capture_file, str) or not capture_file:
        raise InputError(f"{source} event {index} capture_file must be a non-empty string")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or not timestamp:
        raise InputError(f"{source} event {index} timestamp must be a non-empty string")

    for key in record:
        lowered = str(key).lower()
        if lowered in SENSITIVE_KEYS or lowered in SENSITIVE_BYTES_FIELDS:
            raise InputError(
                f"{source} event {index} carries sensitive field '{key}'; "
                "correlation input must be redacted protocol evidence"
            )
    if source == NAS and isinstance(record.get("identity"), dict):
        value = record["identity"].get("value")
        if value is not None:
            raise InputError(
                f"{source} event {index} carries a non-redacted identity value; "
                "regenerate events without --include-sensitive-identifiers"
            )

    event = dict(record)
    event["protocol"] = source
    event["input_order"] = index
    return event


def load_events(path: Path, source: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name} at line {line_number}: {exc.msg}") from exc
            events.append(load_event(record, source, len(events)))
    return events


def parse_timestamp(text: object, index: int) -> float:
    """Convert an ISO-8601 Z timestamp to epoch seconds for window math."""
    from datetime import datetime, timezone

    if not isinstance(text, str):
        raise InputError(f"event {index} timestamp must be a string")
    try:
        instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"event {index} timestamp is not valid ISO-8601: {text!r}") from exc
    if instant.tzinfo is None:
        raise InputError(f"event {index} timestamp lacks a UTC offset")
    return instant.timestamp()


def window_value(requested: float | None) -> float:
    window = DEFAULT_WINDOW_SECONDS if requested is None else float(requested)
    if not 0 <= window <= MAX_WINDOW_SECONDS:
        raise InputError(f"window seconds must be within 0..{MAX_WINDOW_SECONDS:.0f}")
    return window


def _group_record(
    members: list[dict[str, object]],
    strength: str,
    basis: str,
) -> dict[str, object]:
    ordered = sorted(members, key=lambda event: (event["frame_number"], event["timestamp"], event["protocol"], event["input_order"]))
    frames = sorted({event["frame_number"] for event in ordered})
    protocols = sorted({str(event["protocol"]) for event in ordered})
    return {
        "timestamp": ordered[0]["timestamp"],
        "capture_file": ordered[0]["capture_file"],
        "frame_number": frames[0],
        "frame_numbers": frames,
        "protocol_sources": protocols,
        "events": ordered,
        "correlation_strength": strength,
        "evidence": {"level": "DERIVED", "basis": basis},
    }


def correlate(
    ngap_events: Iterable[dict[str, object]],
    nas_events: Iterable[dict[str, object]],
    window: float | None = None,
) -> list[dict[str, object]]:
    """Deterministically group events into correlation records.

    Every input event lands in exactly one group; duplicate events are
    preserved as separate observations and ordering stays stable. Groups
    are sorted by capture, first frame, strength rank, and first
    timestamp so identical input always yields identical output.
    """
    window = window_value(window)
    tagged: list[dict[str, object]] = []
    for index, event in enumerate(ngap_events):
        tagged.append(load_event(event, NGAP, index))
    for index, event in enumerate(nas_events):
        tagged.append(load_event(event, NAS, index))

    groups: list[dict[str, object]] = []
    remaining: list[dict[str, object]] = []
    by_capture: dict[str, dict[int, list[dict[str, object]]]] = {}
    for event in tagged:
        by_capture.setdefault(str(event["capture_file"]), {}).setdefault(event["frame_number"], []).append(event)
    for capture, frames in by_capture.items():
        for frame_number, members in sorted(frames.items()):
            if len(members) >= 2:
                groups.append(
                    _group_record(
                        members,
                        STRONG,
                        f"events from {protocols_of(members)} share capture_file '{capture}' and frame_number {frame_number}",
                    )
                )
            else:
                remaining.extend(members)

    remaining.sort(key=lambda event: (str(event["capture_file"]), event["timestamp"], event["frame_number"], event["protocol"], event["input_order"]))
    chain: list[dict[str, object]] = []
    chain_epoch = None

    def flush_chain() -> None:
        nonlocal chain, chain_epoch
        if not chain:
            return
        if len(chain) >= 2:
            capture = str(chain[0]["capture_file"])
            groups.append(
                _group_record(
                    chain,
                    MEDIUM,
                    f"events from {protocols_of(chain)} share capture_file '{capture}' with adjacent timestamps within the bounded window",
                )
            )
        else:
            event = chain[0]
            groups.append(
                _group_record(
                    [event],
                    WEAK,
                    f"single {event['protocol']} event with capture_file context only; not merged automatically",
                )
            )
        chain = []
        chain_epoch = None

    for event in remaining:
        capture = str(event["capture_file"])
        epoch = parse_timestamp(event["timestamp"], event["input_order"])
        if chain and (str(chain[0]["capture_file"]) != capture or epoch - chain_epoch > window):
            flush_chain()
        chain.append(event)
        chain_epoch = epoch if chain_epoch is None else max(chain_epoch, epoch)
    flush_chain()

    strength_rank = {STRONG: 0, MEDIUM: 1, WEAK: 2}
    groups.sort(
        key=lambda group: (
            str(group["capture_file"]),
            group["frame_number"],
            strength_rank[str(group["correlation_strength"])],
            str(group["timestamp"]),
        )
    )
    return groups


def protocols_of(members: list[dict[str, object]]) -> str:
    return "+".join(sorted({str(event["protocol"]) for event in members}))
