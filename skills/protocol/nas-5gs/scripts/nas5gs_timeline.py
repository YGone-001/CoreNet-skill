#!/usr/bin/env python3
"""Render a bounded protocol-local timeline from detailed NAS-5GS events.

The timeline is a message listing, not a procedure verdict engine: it never
labels REGISTRATION SUCCESS or REGISTRATION FAILURE from local sequencing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nas5gs_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


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
            if "frame_number" not in event or "timestamp" not in event:
                raise InputError(f"event at line {line_number} lacks frame and timestamp provenance")
            events.append(event)
    if not events:
        raise InputError("no detailed NAS-5GS events found")
    return events


def _show(value: object) -> str:
    return str(value) if value is not None else "-"


def _cause(event: dict[str, object]) -> str:
    cause = event.get("cause") if isinstance(event.get("cause"), dict) else {}
    name = cause.get("name")
    code = cause.get("code")
    if name is not None:
        return f"{name}({code})"
    if code is not None:
        return f"UNKNOWN({code})"
    return "-"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    security = event.get("security") if isinstance(event.get("security"), dict) else {}
    identity = event.get("identity") if isinstance(event.get("identity"), dict) else {}
    registration = event.get("registration") if isinstance(event.get("registration"), dict) else {}
    service = event.get("service") if isinstance(event.get("service"), dict) else {}
    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "nas_family": event.get("nas_family"),
        "message_type": event.get("message_type"),
        "support_status": event.get("support_status"),
        "direction": event.get("direction"),
        "security_header_type": security.get("header_type"),
        "integrity_protected": security.get("integrity_protected"),
        "ciphered": security.get("ciphered"),
        "inner_message_available": security.get("inner_message_available"),
        "identity_type": identity.get("type_name"),
        "registration_type": registration.get("type_name"),
        "service_type": service.get("type_name"),
        "cause": event.get("cause"),
    }


def render_text(events: list[dict[str, object]]) -> str:
    lines = []
    for event in events:
        entry = timeline_entry(event)
        protection = "protected" if entry["integrity_protected"] else ("plain" if entry["integrity_protected"] is False else "-")
        if entry["ciphered"]:
            protection += "+ciphered"
        label = entry["message_type"] or f"{entry['support_status']}({entry['nas_family'] or '?'})"
        lines.append(
            f"frame={_show(entry['frame_number'])} {entry['timestamp']} "
            f"{_show(entry['direction'])} {protection} {label} "
            f"reg={_show(entry['registration_type'])} svc={_show(entry['service_type'])} "
            f"id={_show(entry['identity_type'])} cause={_cause(event)}"
        )
    return "\n".join(lines) + "\n"


def render_json(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": [timeline_entry(event) for event in events]}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed NAS-5GS event JSONL")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        events = read_events(args.input)
        rendered = render_text(events) if args.format == "text" else render_json(events)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            if args.input.resolve() == args.output.resolve():
                raise OSError("timeline output must not replace the input artifact")
            if args.output.exists() and not args.force:
                raise OSError(f"output already exists: {args.output}; use --force to replace it")
            if not args.output.parent.is_dir():
                raise OSError(f"output directory does not exist: {args.output.parent}")
            temporary_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp") as temporary:
                    temporary_name = temporary.name
                    temporary.write(rendered)
                os.replace(temporary_name, args.output)
                temporary_name = None
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)
            print(f"wrote timeline for {len(events)} event(s) to {args.output.name}")
    except InputError as exc:
        message = str(exc)
        if "no detailed NAS-5GS events" in message:
            print(f"input error: {message}", file=sys.stderr)
            return EXIT_NO_EVENTS
        print(f"input error: {message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
