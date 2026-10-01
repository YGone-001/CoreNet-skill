#!/usr/bin/env python3
"""Render a unified observed-evidence timeline from correlation groups.

The timeline lists what protocol observations belong together. It is an
Observed Evidence Timeline, not a verdict: it never outputs
registration success, registration failure, or root cause.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from correlate_events import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


def read_groups(path: Path) -> list[dict[str, object]]:
    groups: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                group = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON at line {line_number}: {exc.msg}") from exc
            if not isinstance(group, dict):
                raise InputError(f"correlation record at line {line_number} is not an object")
            for key in ("capture_file", "frame_number", "events", "correlation_strength"):
                if key not in group:
                    raise InputError(f"correlation record at line {line_number} lacks required field: {key}")
            groups.append(group)
    if not groups:
        raise InputError("no correlation groups found")
    return groups


def render_text(groups: list[dict[str, object]]) -> str:
    lines: list[str] = []
    for group in groups:
        header = (
            f"capture={group['capture_file']} frame={group['frame_number']} "
            f"[{group['correlation_strength']}] sources={'+'.join(group['protocol_sources'])}"
        )
        lines.append(header)
        for event in group["events"]:
            label = event.get("message_type") or event.get("procedure_name") or event.get("support_status") or "protocol event"
            lines.append(f"  frame={event.get('frame_number')} {event.get('timestamp')} {event['protocol']}: {label}")
        missing = []
        if "NGAP" not in group["protocol_sources"]:
            missing.append("NGAP")
        if "NAS-5GS" not in group["protocol_sources"]:
            missing.append("NAS-5GS")
        if missing:
            lines.append(f"  missing evidence in this group: {'+'.join(missing)}")
    return "\n".join(lines) + "\n"


def render_json(groups: list[dict[str, object]]) -> str:
    timeline = []
    for group in groups:
        missing = [p for p in ("NGAP", "NAS-5GS") if p not in group["protocol_sources"]]
        timeline.append({
            "timestamp": group.get("timestamp"),
            "capture_file": group.get("capture_file"),
            "frame_number": group.get("frame_number"),
            "frame_numbers": group.get("frame_numbers"),
            "protocol_sources": group["protocol_sources"],
            "correlation_strength": group["correlation_strength"],
            "missing_protocol_sources": missing,
            "events": [
                {
                    "protocol": event.get("protocol"),
                    "timestamp": event.get("timestamp"),
                    "frame_number": event.get("frame_number"),
                    "message_type": event.get("message_type"),
                    "procedure_name": event.get("procedure_name"),
                    "support_status": event.get("support_status"),
                }
                for event in group["events"]
            ],
            "evidence": group.get("evidence"),
        })
    return json.dumps({"timeline": timeline}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="correlation-event JSONL from correlate-events.py")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        groups = read_groups(args.input)
        rendered = render_text(groups) if args.format == "text" else render_json(groups)
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
            print(f"wrote timeline for {len(groups)} group(s) to {args.output.name}")
    except InputError as exc:
        message = str(exc)
        if "no correlation groups" in message:
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
