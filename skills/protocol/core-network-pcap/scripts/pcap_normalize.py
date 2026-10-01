#!/usr/bin/env python3
"""Shared, standalone helpers for metadata-only capture normalization."""

from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Iterable, Iterator


EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_FRAMES = 6
EXIT_OUTPUT_FAILURE = 7

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "sctp.srcport",
    "sctp.dstport",
)

CLASSIFICATIONS = {
    "ngap": "NGAP",
    "nas-eps": "NAS_EPS",
    "nas_eps": "NAS_EPS",
    "nas-5gs": "NAS_5GS",
    "nas_5gs": "NAS_5GS",
    "s1ap": "S1AP",
    "gtpv2": "GTPV2",
    "gtp": "GTPU",
    "pfcp": "PFCP",
    "diameter": "DIAMETER",
    "sip": "SIP",
    "sdp": "SDP",
    "rtp": "RTP",
    "http2": "HTTP2",
    "http/2": "HTTP2",
    "tls": "TLS",
    "sctp": "SCTP",
    "tcp": "TCP",
    "udp": "UDP",
    "ipv6": "IP",
    "ip": "IP",
}


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested generic fields."""


@dataclass(frozen=True)
class FrameMetadata:
    """Observed generic metadata retained outside the shared event shape."""

    stack: str
    classification: str
    transport: str | None
    address_families: tuple[str, ...]
    endpoints: tuple[tuple[str | None, int | None], ...]


def safe_capture_name(path: Path) -> str:
    """Return a basename so outputs do not disclose workstation paths."""
    return path.name


def clean(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_port(value: object, field: str) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        port = int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer port") from exc
    if not 0 <= port <= 65535:
        raise InputError(f"{field} is outside the valid port range")
    return port


def normalize_timestamp(value: object) -> str:
    """Convert tshark epoch seconds to UTC ISO-8601 with microsecond precision."""
    text = clean(value)
    if text is None:
        raise InputError("frame.time_epoch is required")
    try:
        epoch = Decimal(text)
    except InvalidOperation as exc:
        raise InputError("frame.time_epoch is not a valid epoch timestamp") from exc
    if not epoch.is_finite():
        raise InputError("frame.time_epoch must be finite")
    microseconds = int((epoch * Decimal("1000000")).to_integral_value(rounding=ROUND_HALF_EVEN))
    try:
        instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    except OverflowError as exc:
        raise InputError("frame.time_epoch is outside the supported UTC range") from exc
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def protocol_stack(value: object) -> tuple[str, tuple[str, ...]]:
    raw = clean(value) or ""
    tokens = tuple(token.strip().lower() for token in raw.split(":") if token.strip())
    return raw, tokens


def classify_stack(tokens: tuple[str, ...]) -> str:
    """Classify only direct tshark stack observations; never use port heuristics."""
    for token in reversed(tokens):
        if token in CLASSIFICATIONS:
            return CLASSIFICATIONS[token]
    return "UNKNOWN"


def observed_transport(tokens: tuple[str, ...]) -> str | None:
    for token in reversed(tokens):
        if token in {"sctp", "tcp", "udp"}:
            return token.upper()
    return None


def endpoint(record: dict[str, object], direction: str, transport: str | None) -> dict[str, object] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"{transport.lower()}.{direction}port"), f"{transport.lower()}.{direction}port") if transport else None
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def normalize_record(record: object, capture_file: str) -> tuple[dict[str, object], FrameMetadata]:
    if not isinstance(record, dict):
        raise InputError("structured frame record must be a JSON object")
    frame_text = clean(record.get("frame.number"))
    if frame_text is None:
        raise InputError("frame.number is required")
    try:
        frame_number = int(frame_text)
    except ValueError as exc:
        raise InputError("frame.number must be an integer") from exc
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")

    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    raw_stack, tokens = protocol_stack(record.get("frame.protocols"))
    classification = classify_stack(tokens)
    transport = observed_transport(tokens)
    source = endpoint(record, "src", transport)
    destination = endpoint(record, "dst", transport)
    families: list[str] = []
    if clean(record.get("ip.src")) or clean(record.get("ip.dst")):
        families.append("IPv4")
    if clean(record.get("ipv6.src")) or clean(record.get("ipv6.dst")):
        families.append("IPv6")
    stream = clean(record.get(f"{transport.lower()}.stream")) if transport in {"TCP", "UDP"} else None

    source_ref = f"capture:{capture_file}#frame={frame_number}"
    if raw_stack:
        source_ref += f"; tshark-stack={raw_stack}"
    event: dict[str, object] = {
        "timestamp": timestamp,
        "protocol": classification,
        "packet": {"frame_number": frame_number, "capture_file": capture_file},
        "evidence": {"level": "OBSERVED", "source": source_ref},
    }
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    if stream is not None:
        event["correlation"] = {"stream_id": stream}

    endpoints = tuple(
        (item.get("address"), item.get("port"))
        for item in (source, destination)
        if item is not None
    )
    return event, FrameMetadata(raw_stack, classification, transport, tuple(families), endpoints)


def read_jsonl(path: Path) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON Lines record at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"JSON Lines record at line {line_number} is not an object")
            yield record


def tshark_version() -> str:
    try:
        completed = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(capture: Path) -> list[str]:
    command = ["tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        command.extend(["-e", field])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    command = build_tshark_fields_command(capture)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
    if tuple(header) != FIELDS:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark did not expose the required generic fields: {stderr or header}")
    for row in reader:
        if len(row) > len(FIELDS):
            raise TsharkError("tshark returned more columns than the requested generic field set")
        padded = row + [""] * (len(FIELDS) - len(row))
        yield dict(zip(FIELDS, padded, strict=True))
    stderr = process.stderr.read().strip() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise TsharkError(f"tshark capture parsing failed: {stderr or f'exit {return_code}'}")


def input_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        return "capture"
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    raise InputError("cannot infer input format; use --input-format capture or fields-jsonl")


def records_for_input(path: Path, requested: str) -> tuple[Iterable[dict[str, object]], str | None]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    kind = input_kind(path, requested)
    if kind == "fields-jsonl":
        return read_jsonl(path), None
    if kind == "capture":
        return tshark_records(path), tshark_version()
    raise InputError(f"unsupported extracted format: {kind}")
