#!/usr/bin/env python3
"""Extract bounded GTPv2-C session-control events from a capture, PDML or fields JSONL.

Direct capture input is decoded by the installed `tshark` dissector in PDML
form so that grouped Bearer Context boundaries are preserved. Structured input
never requires TShark.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gtpv2_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    EXIT_TOOL_UNAVAILABLE,
    EXIT_TSHARK_FAILURE,
    InputError,
    TsharkError,
    ToolUnavailable,
    events_for_input,
    project_trace_event,
    tshark_version,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="PCAP/PCAPNG capture, PDML document or GTPv2-C fields JSONL")
    parser.add_argument(
        "--input-format",
        choices=("auto", "capture", "pdml", "fields-jsonl"),
        default="auto",
        help="input interpretation; auto uses the file extension",
    )
    parser.add_argument("--output", type=Path, help="detailed GTPv2-C event JSONL destination")
    parser.add_argument("--trace-output", type=Path, help="shared trace-event JSONL projection destination")
    parser.add_argument("--force", action="store_true", help="explicitly replace existing output files")
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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.output is None and args.trace_output is None:
        print("no destination requested; pass --output and/or --trace-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    try:
        events, decoder = events_for_input(args.input, args.input_format)
        collected = list(events)
        if not collected:
            raise InputError("input contains no GTPv2-C records")
        if decoder is not None:
            print(f"decoder: {decoder}", file=sys.stderr)
        if args.output is not None:
            check_destination(args.input, args.output, args.force)
            write_jsonl(args.output, collected)
            print(f"wrote {len(collected)} detailed GTPv2-C event(s) to {args.output.name}")
        if args.trace_output is not None:
            check_destination(args.input, args.trace_output, args.force)
            write_jsonl(args.trace_output, [project_trace_event(event) for event in collected])
            print(f"wrote {len(collected)} trace-event projection(s) to {args.trace_output.name}")
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return EXIT_TOOL_UNAVAILABLE
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return EXIT_TSHARK_FAILURE
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no GTPv2-C records" in str(exc) else EXIT_MALFORMED_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
