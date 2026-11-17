#!/usr/bin/env python3
"""Extract bounded, privacy-safe SIP message observations.

Capture input is dissected by the installed TShark in PDML form. Stored PDML and
sanitized dissector-record JSONL are also accepted so the protocol event model can
be replayed deterministically without a decoder.

The extractor publishes SIP requests and responses only. It does not correlate
transactions or dialogs and assigns no IMS registration or call semantics.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sip_model import (  # noqa: E402
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    EXIT_TOOL_UNAVAILABLE,
    EXIT_TSHARK_FAILURE,
    InputError,
    ToolUnavailable,
    TsharkError,
    events_for_input,
    project_trace_event,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        type=Path,
        help="PCAP/PCAPNG capture, stored PDML document or sanitized dissector-record JSONL",
    )
    parser.add_argument(
        "--input-format",
        choices=("auto", "capture", "pdml", "fields-jsonl"),
        default="auto",
        help="input interpretation; auto uses the file extension",
    )
    parser.add_argument("--output", type=Path, help="SIP event JSONL destination")
    parser.add_argument(
        "--trace-output", type=Path, help="shared trace-event JSONL projection destination"
    )
    parser.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return parser


def check_destination(source: Path, destination: Path, force: bool) -> None:
    if destination.exists() and destination.resolve() == source.resolve():
        raise OSError("output must not replace the input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def write_jsonl(destination: Path, rows: list[dict]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            newline="\n",
        ) as handle:
            temporary = handle.name
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def _require_published(destination: Path, label: str) -> None:
    try:
        if not destination.is_file():
            raise OSError(f"{label} was not published")
        destination.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"{label} is missing or unreadable: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output is None and args.trace_output is None:
        print("no destination requested; pass --output and/or --trace-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        events, decoder = events_for_input(args.input, args.input_format)
        if not events:
            print("input contains no SIP messages", file=sys.stderr)
            return EXIT_NO_EVENTS
        if decoder is not None:
            print(f"decoder: {decoder}", file=sys.stderr)
        if args.output is not None:
            check_destination(args.input, args.output, args.force)
            write_jsonl(args.output, events)
            _require_published(args.output, "SIP event output")
            print(f"wrote {len(events)} SIP event(s) to {args.output.name}")
        if args.trace_output is not None:
            check_destination(args.input, args.trace_output, args.force)
            trace_events = [
                project_trace_event(event) for event in events if event["timestamp"] is not None
            ]
            write_jsonl(args.trace_output, trace_events)
            _require_published(args.trace_output, "trace-event output")
            print(f"wrote {len(trace_events)} trace-event projection(s) to {args.trace_output.name}")
            omitted = len(events) - len(trace_events)
            if omitted:
                print(
                    f"omitted {omitted} trace projection(s) without a source timestamp",
                    file=sys.stderr,
                )
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return EXIT_TOOL_UNAVAILABLE
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return EXIT_TSHARK_FAILURE
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())