#!/usr/bin/env python3
"""Protocol-local SBI HTTP/2 request/response transaction correlation.

Transactions are scoped by capture, HTTP/2 connection context, and stream ID.
A stream ID alone never correlates transactions across independent TCP connections.
The transaction key is DERIVED and is not a standardized 3GPP identifier.

This script never models complete PDU Session lifecycle and never states that
a telecom procedure or user-plane path succeeded.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sbi_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    correlate_events,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("events", type=Path, help="detailed SBI HTTP/2 event JSONL input")
    result.add_argument("--output", type=Path, required=True, help="correlation summary JSON destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output file")
    return result


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")

    events: list[dict[str, object]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"unable to read events file: {path}: {exc}") from exc

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(f"invalid JSON at line {line_number} of {path}: {exc}") from exc
        if not isinstance(event, dict):
            raise InputError(f"event at line {line_number} of {path} is not a JSON object")
        if "frame_number" not in event or "capture_file" not in event:
            raise InputError(f"event at line {line_number} lacks frame provenance")
        events.append(event)

    if not events:
        raise InputError("no detailed SBI HTTP/2 events found in input")
    return events


def write_correlation(events_path: Path, output: Path, force: bool) -> int:
    if events_path.resolve() == output.resolve():
        raise OSError("output must not replace the input events file")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")

    events = read_events(events_path)
    summary = correlate_events(events)

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            json.dump(summary, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
        os.replace(temporary_name, output)
        temporary_name = None
        total = len(summary.get("transactions", [])) + len(summary.get("open_transactions", []))
        return total
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    args = parser().parse_args()
    try:
        count = write_correlation(args.events, args.output, args.force)
        print(f"correlated {count} transaction(s)")
        return 0
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
