#!/usr/bin/env python3
"""Correlate bounded Diameter base-protocol events into local transactions.

The output is protocol-local evidence only. It never asserts a telecom
procedure outcome, timeout, peer failure or application-level success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diameter_core_model import EXIT_MALFORMED_INPUT, EXIT_OUTPUT_FAILURE, InputError, correlate, render_timeline


def read_events(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid event JSON on line {line_number}: {exc}") from exc
            if not isinstance(row, dict) or row.get("protocol") is not None and row.get("protocol") != "Diameter":
                raise InputError(f"line {line_number} is not a Diameter event")
            if not all(key in row for key in ("frame_number", "message_occurrence", "direction", "transport")):
                raise InputError(f"line {line_number} is missing required event fields")
            rows.append(row)
    return rows


def write_text(destination: Path, text: str) -> None:
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
            handle.write(text)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="Diameter event JSONL produced by extract-diameter-core.py")
    parser.add_argument("--output", type=Path, help="transaction JSON destination")
    parser.add_argument("--timeline-output", type=Path, help="protocol-local text timeline destination")
    parser.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    args = parser.parse_args(argv)
    if args.output is None and args.timeline_output is None:
        print("no destination requested; pass --output and/or --timeline-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        events = read_events(args.events)
        if not events:
            raise InputError("event input contains no Diameter records")
        document = correlate(events)
        if args.output is not None:
            if args.output.exists() and not args.force:
                raise OSError(f"output already exists: {args.output}; use --force to replace it")
            write_text(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
            print(f"wrote {document['transaction_count']} transaction(s) to {args.output.name}")
        if args.timeline_output is not None:
            if args.timeline_output.exists() and not args.force:
                raise OSError(f"output already exists: {args.timeline_output}; use --force to replace it")
            write_text(args.timeline_output, render_timeline(document))
            print(f"wrote timeline to {args.timeline_output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())