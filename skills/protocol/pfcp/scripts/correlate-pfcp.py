#!/usr/bin/env python3
"""Protocol-local PFCP request/response transaction correlation.

Transactions are scoped by capture, endpoint pair, sequence number and
compatible message family. A sequence number alone never correlates two
peers: two independent PFCP peer pairs may reuse the same sequence number,
and the same numeric SEID may exist in unrelated endpoint contexts.

The summary preserves every observed frame. Repeated requests sharing one
transaction are reported as duplicate/retransmission candidates; original
evidence is never deleted or deduplicated. Input order is not authoritative:
a response record may appear before its request record in the JSONL input,
and correlation still succeeds because the grouping key is order-independent.

This script never models a PDU Session lifecycle and never states that a
session or user-plane path works.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pfcp_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    ROLE_REQUEST,
    ROLE_RESPONSE,
    endpoint_pair,
    optional_int,
    resolve_message,
    transaction_key,
)


def read_events(path: Path) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(event, dict):
                raise InputError(f"event at line {line_number} is not an object")
            if "frame_number" not in event or "capture_file" not in event:
                raise InputError(f"event at line {line_number} lacks frame provenance")
            events.append(event)
    if not events:
        raise InputError("no detailed PFCP events found")
    return events


def _header(event: dict[str, object]) -> dict[str, object]:
    header = event.get("header")
    return header if isinstance(header, dict) else {}


def correlate(events: list[dict[str, object]]) -> dict[str, object]:
    """Group events into protocol-local PFCP transactions."""
    capture_file: str | None = None
    groups: dict[str, dict[str, object]] = {}
    unbound_events: list[dict[str, object]] = []

    for event in events:
        if capture_file is None:
            capture_file = str(event.get("capture_file")) if event.get("capture_file") is not None else None
        header = _header(event)
        code = optional_int(header.get("message_type_code"))
        sequence = optional_int(header.get("sequence_number"))
        if code is None or sequence is None:
            unbound_events.append({
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "message_type": header.get("message_type"),
                "support_status": event.get("support_status"),
                "limitation": "message type or sequence number absent; no transaction evidence",
            })
            continue
        identity = resolve_message(code)
        if identity.transaction_role is None:
            unbound_events.append({
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "message_type": identity.message_type,
                "support_status": event.get("support_status"),
                "limitation": "message has no reviewed request/response role; no transaction correlation",
            })
            continue
        key = transaction_key(event)
        group = groups.setdefault(key, {
            "transaction_key": key,
            "capture_file": event.get("capture_file"),
            "endpoint_pair": endpoint_pair(event),
            "sequence_number": sequence,
            "family": identity.family,
            "request_frames": [],
            "response_frames": [],
            "message_types": [],
            "header_seids": [],
            "limitations": [],
        })
        if identity.transaction_role == ROLE_REQUEST:
            group["request_frames"].append(event.get("frame_number"))
        elif identity.transaction_role == ROLE_RESPONSE:
            group["response_frames"].append(event.get("frame_number"))
        if identity.message_type not in group["message_types"]:
            group["message_types"].append(identity.message_type)
        seid = optional_int(header.get("seid"))
        if seid is not None and seid not in group["header_seids"]:
            group["header_seids"].append(seid)

    transactions: list[dict[str, object]] = []
    open_transactions: list[dict[str, object]] = []
    limitations: list[str] = []

    for key in sorted(groups):
        group = groups[key]
        requests = sorted(frame for frame in group["request_frames"] if frame is not None)
        responses = sorted(frame for frame in group["response_frames"] if frame is not None)
        entry = {
            "transaction_key": group["transaction_key"],
            "capture_file": group["capture_file"],
            "endpoint_pair": group["endpoint_pair"],
            "sequence_number": group["sequence_number"],
            "family": group["family"],
            "request_frames": requests,
            "response_frames": responses,
            "correlation_strength": "WEAK",
            "message_types": list(group["message_types"]),
            "header_seids": sorted(group["header_seids"]),
            "duplicate_request_candidates": requests[1:] if len(requests) > 1 else [],
            "limitations": [],
        }
        if requests and responses:
            entry["correlation_strength"] = "STRONG" if len(requests) == 1 and len(responses) == 1 else "MEDIUM"
            if len(requests) > 1:
                entry["limitations"].append("more than one request frame shares this transaction evidence; candidates only, all frames preserved")
            if len(responses) > 1:
                entry["limitations"].append("more than one response frame shares this transaction evidence; all frames preserved")
            transactions.append(entry)
        else:
            if requests:
                entry["limitations"].append("request observed without a matching response inside the capture window")
            else:
                entry["limitations"].append("response observed without a matching request inside the capture window")
            entry["limitations"].append("partial capture boundary; this is not evidence of a network failure")
            open_transactions.append(entry)

    if open_transactions:
        limitations.append("some PFCP transactions are open inside the capture window; absence of a counterpart is not a network failure")
    if unbound_events:
        limitations.append("some events carried no transaction evidence and were left unbound")

    return {
        "capture_file": capture_file,
        "transactions": transactions,
        "open_transactions": open_transactions,
        "unbound_events": sorted(unbound_events, key=lambda item: (str(item.get("frame_number")), str(item.get("timestamp")))),
        "limitations": limitations,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed PFCP event JSONL")
    result.add_argument("--output", type=Path, required=True, help="transaction correlation summary JSON destination")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def write_summary(input_path: Path, output: Path, force: bool) -> int:
    if input_path.resolve() == output.resolve():
        raise OSError("output must not replace the input artifact")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    summary = correlate(read_events(input_path))
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            temporary.write(json.dumps(summary, sort_keys=True, indent=2) + "\n")
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
    return len(summary["transactions"])


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        closed = write_summary(args.input, args.output, args.force)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed PFCP events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(f"correlated {closed} closed transaction(s) -> {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
