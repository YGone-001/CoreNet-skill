#!/usr/bin/env python3
"""Render a concise protocol-local timeline from detailed NAS-EPS events.

The timeline shows observed message identity, protection state, direction and
EMM cause only. It never decodes ciphered content, never interprets a procedure
outcome, and never reports subscriber identity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nas_eps_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


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
        raise InputError("no detailed NAS-EPS events found")
    return events


def _cause(cause: object) -> str:
    if not isinstance(cause, dict):
        return "-"
    value = cause.get("value")
    if value is None:
        return "-"
    name = cause.get("name")
    return f"emm:{value}:{name}" if name else f"emm:{value}"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "message_type_code": event.get("message_type_code"),
        "message_type": event.get("message_type"),
        "support_status": event.get("support_status"),
        "procedure": event.get("procedure"),
        "result": event.get("result"),
        "direction": event.get("direction"),
        "security_header_type": event.get("security_header_type"),
        "protection": event.get("protection"),
        "emm_cause": event.get("emm_cause"),
        "attach_type": event.get("attach_type"),
        "identity_type_value": event.get("identity_type_value"),
        "esm_container_present": event.get("esm_container_present"),
        "esm_container_length": event.get("esm_container_length"),
        "ciphered_payload_present": event.get("ciphered_payload_present"),
    }


def render_text(events: list[dict[str, object]]) -> str:
    lines = []
    for event in events:
        entry = timeline_entry(event)
        label = entry["message_type"] or (entry["support_status"] or "UNKNOWN")
        line = (
            f"frame={entry['frame_number'] if entry['frame_number'] is not None else '-'} "
            f"{entry['timestamp']} "
            f"{entry['direction'] or '-'} {label} "
            f"protection={entry['protection'] or '-'} "
            f"result={entry['result'] or '-'} cause={_cause(entry['emm_cause'])}"
        )
        if entry["attach_type"]:
            attach = entry["attach_type"]
            name = attach.get("name") if isinstance(attach, dict) else None
            line += f" attach-type={attach.get('value') if isinstance(attach, dict) else '-'}"
            if name:
                line += f":{name}"
        if entry["identity_type_value"] is not None:
            line += f" identity-type={entry['identity_type_value']}"
        if entry["esm_container_present"]:
            line += f" esm-container-bytes={entry['esm_container_length']}"
        if entry["ciphered_payload_present"]:
            line += " ciphered-payload=yes"
        if entry["support_status"] != "SUPPORTED":
            line += f" support={entry['support_status']}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def render_json(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": [timeline_entry(event) for event in events]}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed NAS-EPS event JSONL")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true")
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
                with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", delete=False, dir=args.output.parent,
                    prefix=f".{args.output.name}.", suffix=".tmp",
                ) as temporary:
                    temporary_name = temporary.name
                    temporary.write(rendered)
                os.replace(temporary_name, args.output)
                temporary_name = None
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)
            print(f"wrote timeline for {len(events)} event(s) to {args.output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed NAS-EPS events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
