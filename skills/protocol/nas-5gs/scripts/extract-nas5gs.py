#!/usr/bin/env python3
"""Extract bounded NAS-5GS (5GMM) semantic events from a capture or JSONL.

Outputs detailed NAS-5GS JSONL events and, optionally, a shared trace-event
projection. Subscriber identity values stay redacted by default; see
--include-sensitive-identifiers for the explicit opt-in. Authentication
secret material is never emitted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nas5gs_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    EXIT_TSHARK_FAILURE,
    EXIT_TOOL_UNAVAILABLE,
    InputError,
    TsharkError,
    ToolUnavailable,
    normalize_record,
    project_trace_event,
    records_for_input,
    safe_capture_name,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="PCAP/PCAPNG capture or structured NAS-5GS fields JSONL")
    result.add_argument("--input-format", choices=("auto", "capture", "fields-jsonl"), default="auto")
    result.add_argument("--output", type=Path, help="detailed NAS-5GS event JSONL destination")
    result.add_argument("--trace-output", type=Path, help="shared trace-event JSONL projection destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    result.add_argument(
        "--include-sensitive-identifiers",
        action="store_true",
        help="opt-in: carry identity_value from structured input into detailed events. "
        "Raw subscriber/mobile identity values are sensitive operational data; the default "
        "redacts them to presence and type only. Authentication secrets are never emitted.",
    )
    return result


def write_events(input_path: Path, input_format: str, output: Path, force: bool, include_sensitive: bool) -> int:
    if input_path.resolve() == output.resolve():
        raise OSError("output must not replace the input artifact")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    records, _version = records_for_input(input_path, input_format)
    capture_file = safe_capture_name(input_path)
    count = 0
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            for record in records:
                event = normalize_record(record, capture_file, include_sensitive=include_sensitive)
                temporary.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
        if count == 0:
            raise InputError("input contains no NAS-5GS records")
        os.replace(temporary_name, output)
        temporary_name = None
        return count
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def write_projection(events_path: Path, output: Path, force: bool) -> int:
    if events_path.resolve() == output.resolve():
        raise OSError("trace output must not replace the detailed event file")
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    count = 0
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            for line in events_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise InputError(f"invalid detailed event JSON: {exc.msg}") from exc
                if not isinstance(event, dict):
                    raise InputError("detailed NAS-5GS event line is not an object")
                temporary.write(json.dumps(project_trace_event(event), sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
        if count == 0:
            raise InputError("detailed NAS-5GS event file is empty")
        os.replace(temporary_name, output)
        temporary_name = None
        return count
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.output is None and args.trace_output is None:
        print("no destination requested; pass --output and/or --trace-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        if args.output is not None:
            count = write_events(args.input, args.input_format, args.output, args.force, args.include_sensitive_identifiers)
            print(f"wrote {count} detailed NAS-5GS event(s) to {args.output.name}")
        if args.trace_output is not None:
            if args.output is None:
                with tempfile.TemporaryDirectory() as directory:
                    staged = Path(directory) / "nas5gs-events.jsonl"
                    write_events(args.input, args.input_format, staged, False, args.include_sensitive_identifiers)
                    projected = write_projection(staged, args.trace_output, args.force)
            else:
                projected = write_projection(args.output, args.trace_output, args.force)
            print(f"wrote {projected} trace-event projection(s) to {args.trace_output.name}")
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return EXIT_TOOL_UNAVAILABLE
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return EXIT_TSHARK_FAILURE
    except InputError as exc:
        message = str(exc)
        if "no NAS-5GS records" in message or "empty" in message:
            print(f"input error: {message}", file=sys.stderr)
            return EXIT_NO_EVENTS
        print(f"input error: {message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
