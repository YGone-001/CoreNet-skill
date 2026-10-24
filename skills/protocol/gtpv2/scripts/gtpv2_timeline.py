#!/usr/bin/env python3
"""Render a protocol-local GTPv2-C timeline from detailed event JSONL."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gtpv2_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, InputError


def read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"invalid JSON at line {number}: {exc.msg}") from exc
        if not isinstance(event, dict):
            raise InputError(f"event at line {number} is not an object")
        for field in ("frame_number", "timestamp", "message_type"):
            if field not in event:
                raise InputError(f"event at line {number} lacks {field}")
        events.append(event)
    if not events:
        raise InputError("no detailed GTPv2-C events found")
    return events


def endpoint_text(event: dict[str, Any], role: str) -> str:
    endpoint = event.get(role) or {}
    address = endpoint.get("address") or "-"
    port = endpoint.get("port")
    return f"{address}:{port}" if port is not None else str(address)


def teid_text(event: dict[str, Any]) -> str:
    header = event.get("header") or {}
    state = header.get("teid_state")
    value = header.get("teid")
    if state == "PRESENT":
        return f"PRESENT(0x{value:08x})"
    if state == "ZERO":
        return "ZERO"
    return "ABSENT"


def line_for(event: dict[str, Any]) -> str:
    header = event.get("header") or {}
    parts = [
        str(event.get("timestamp")),
        f"frame {event.get('frame_number'):>5}",
        str(event.get("message_type") or "UNKNOWN"),
        f"{endpoint_text(event, 'source')} -> {endpoint_text(event, 'destination')}",
        f"teid={teid_text(event)}",
        f"seq={header.get('sequence_number')}",
    ]
    cause = event.get("message_cause")
    if isinstance(cause, dict):
        parts.append(f"cause={cause.get('cause_code')}({cause.get('cause_name')})")
    contexts = event.get("bearer_contexts") or []
    if contexts:
        ebis = [str(item.get("ebi")) for item in contexts if item.get("ebi") is not None]
        parts.append(f"bearers={len(contexts)}")
        if ebis:
            parts.append(f"ebi={','.join(ebis)}")
    if event.get("support_status") and event["support_status"] != "SUPPORTED":
        parts.append(f"status={event['support_status']}")
    return "  ".join(parts)


def render_text(events: list[dict[str, Any]]) -> str:
    captures = sorted({str(event.get("capture_file")) for event in events})
    lines = [
        f"GTPv2-C timeline: {len(events)} event(s)",
        f"capture: {', '.join(captures)}",
        "scope: protocol-local observations only; no session or bearer verdict is implied",
        "",
    ]
    lines.extend(line_for(event) for event in events)
    return "\n".join(lines) + "\n"


def projection(event: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "message_type": event.get("message_type"),
        "message_type_code": event.get("message_type_code"),
        "procedure_family": event.get("procedure_family"),
        "support_status": event.get("support_status"),
        "source": event.get("source"),
        "destination": event.get("destination"),
        "header": event.get("header"),
        "message_cause": event.get("message_cause"),
        "bearer_contexts": event.get("bearer_contexts") or [],
    }
    if event.get("hierarchy_basis"):
        payload["hierarchy_basis"] = event["hierarchy_basis"]
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="detailed GTPv2-C event JSONL")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        events = read_events(args.input)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed GTPv2-C events" in str(exc) else EXIT_MALFORMED_INPUT
    if args.format == "json":
        payload = {
            "protocol": "GTPv2-C",
            "capture_files": sorted({str(event.get("capture_file")) for event in events}),
            "event_count": len(events),
            "events": [projection(event) for event in events],
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(events))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
