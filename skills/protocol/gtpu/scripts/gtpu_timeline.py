#!/usr/bin/env python3
"""Render a concise protocol-local timeline from detailed GTP-U events.

The timeline shows observed message identity, outer endpoints, TEID,
optional sequence number, bounded PDU Session Container evidence, a bounded
inner packet summary, and End Marker / Error Indication observations. It
never prints a tunnel, user-plane, packet-loss, or session verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gtpu_model import EXIT_MALFORMED_INPUT, EXIT_NO_EVENTS, EXIT_OUTPUT_FAILURE, InputError


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
        raise InputError("no detailed GTP-U events found")
    return events


def _show(value: object) -> str:
    return str(value) if value not in (None, "") else "-"


def _inner_summary(event: dict[str, object]) -> str:
    inner = event.get("inner_packet")
    if not isinstance(inner, dict):
        return "-"
    if inner.get("opaque"):
        return f"opaque(ipv{_show(inner.get('ip_version'))})"
    parts = []
    if inner.get("ip_version") is not None:
        parts.append(f"ipv{inner['ip_version']}")
    if inner.get("source_address"):
        parts.append(f"{inner['source_address']}:{_show(inner.get('source_port'))}")
    if inner.get("destination_address"):
        parts.append(f"->{inner['destination_address']}:{_show(inner.get('destination_port'))}")
    if inner.get("protocol") is not None:
        parts.append(f"proto={inner['protocol']}")
    if inner.get("length") is not None:
        parts.append(f"len={inner['length']}")
    return " ".join(parts) if parts else "-"


def _container_summary(event: dict[str, object]) -> str:
    container = event.get("pdu_session_container")
    if not isinstance(container, dict):
        return "-"
    parts = []
    if container.get("pdu_type_name"):
        parts.append(str(container["pdu_type_name"]))
    if container.get("qfi") is not None:
        parts.append(f"qfi={container['qfi']}")
    if container.get("rqi") is not None:
        parts.append(f"rqi={int(bool(container['rqi']))}")
    if container.get("ppi") is not None:
        parts.append(f"ppi={container['ppi']}")
    return " ".join(parts) if parts else "-"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    outer = event.get("outer") if isinstance(event.get("outer"), dict) else {}
    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "message_type": header.get("message_type"),
        "support_status": event.get("support_status"),
        "outer_source": outer.get("source_address"),
        "outer_destination": outer.get("destination_address"),
        "outer_source_port": outer.get("source_port"),
        "outer_destination_port": outer.get("destination_port"),
        "teid": header.get("teid"),
        "sequence_number": header.get("sequence_number"),
        "pdu_session_container": event.get("pdu_session_container"),
        "inner_packet": event.get("inner_packet"),
        "end_marker": event.get("end_marker"),
        "error_indication": event.get("error_indication"),
        "extension_headers": event.get("extension_headers"),
    }


def render_text(events: list[dict[str, object]]) -> str:
    ordered = sorted(events, key=lambda item: (str(item.get("timestamp")), item.get("frame_number") or 0))
    lines = []
    for event in ordered:
        entry = timeline_entry(event)
        label = entry["message_type"] or f"{entry['support_status']}()"
        line = (
            f"frame={_show(entry['frame_number'])} {entry['timestamp']} "
            f"{_show(entry['outer_source'])}:{_show(entry['outer_source_port'])} -> "
            f"{_show(entry['outer_destination'])}:{_show(entry['outer_destination_port'])} "
            f"{label} teid={_show(entry['teid'])} seq={_show(entry['sequence_number'])} "
            f"container={_container_summary(event)} inner={_inner_summary(event)}"
        )
        if entry["end_marker"]:
            line += " end-marker=yes"
        if entry["error_indication"]:
            line += f" error-indication affected-teid={_show(entry['error_indication'].get('affected_teid'))}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def render_json(events: list[dict[str, object]]) -> str:
    ordered = sorted(events, key=lambda item: (str(item.get("timestamp")), item.get("frame_number") or 0))
    return json.dumps({"events": [timeline_entry(event) for event in ordered]}, sort_keys=True, indent=2) + "\n"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="detailed GTP-U event JSONL")
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
        return EXIT_NO_EVENTS if "no detailed GTP-U events" in str(exc) else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
