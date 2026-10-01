#!/usr/bin/env python3
"""Render a concise protocol-local timeline from detailed NGAP events.

The timeline shows observed message identity, UE NGAP IDs, and cause
category/value only. It never adds NAS interpretation or root cause.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ngap_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


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
        raise InputError("no detailed NGAP events found")
    return events


def _id(value: object) -> str:
    return str(value) if value is not None else "-"


def _cause(cause: object) -> str:
    if not isinstance(cause, dict):
        return "-"
    category = cause.get("category")
    value = cause.get("value")
    if category is None and value is None:
        return "-"
    if value is None:
        return str(category)
    return f"{category}:{value}"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "pdu_type": event.get("pdu_type"),
        "message_type": event.get("message_type"),
        "procedure_name": event.get("procedure_name"),
        "support_status": event.get("support_status"),
        "result": event.get("result"),
        "sender_role": event.get("sender_role"),
        "ran_ue_ngap_id": event.get("ran_ue_ngap_id"),
        "amf_ue_ngap_id": event.get("amf_ue_ngap_id"),
        "cause": event.get("cause"),
    }


def render_text(events: list[dict[str, object]]) -> str:
    lines = []
    for event in events:
        entry = timeline_entry(event)
        lines.append(
            f"frame={_id(entry['frame_number'])} {entry['timestamp']} "
            f"{entry['pdu_type'] or '-'} {entry['message_type'] or entry['procedure_name'] or (entry['support_status'] or 'UNKNOWN')} "
            f"ran={_id(entry['ran_ue_ngap_id'])} amf={_id(entry['amf_ue_ngap_id'])} "
            f"result={entry['result'] or '-'} cause={_cause(entry['cause'])}"
        )
    return "\n".join(lines) + "\n"


def render_json(events: list[dict[str, object]]) -> str:
    return json.dumps({"events": [timeline_entry(event) for event in events]}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed NGAP event JSONL")
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
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no detailed NGAP events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
