#!/usr/bin/env python3
"""Extract bounded 3GPP SBI and HTTP/2 events on N11 from a capture or JSONL.

Outputs detailed SBI HTTP/2 JSONL events and, optionally, a shared trace-event
projection. NAS, NGAP, PFCP, and GTP-U semantics are never decoded, and no
raw HTTP/2 byte parser is implemented: only TShark dissector output or structured
offline input is used.
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
    result.add_argument("input", type=Path, help="PCAP/PCAPNG capture or structured SBI HTTP/2 fields JSONL")
    result.add_argument("--input-format", choices=("auto", "capture", "fields-jsonl"), default="auto")
    result.add_argument("--output", type=Path, help="detailed SBI HTTP/2 event JSONL destination")
    result.add_argument("--trace-output", type=Path, help="shared trace-event JSONL projection destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return result


def write_events(input_path: Path, input_format: str, output: Path, force: bool) -> int:
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
                event = normalize_record(record, capture_file)
                temporary.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
        if count == 0:
            raise InputError("input contains no SBI HTTP/2 records")
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
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise InputError("detailed event line is not an object")
                temporary.write(json.dumps(project_trace_event(event), sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
        if count == 0:
            raise InputError("detailed SBI HTTP/2 event file is empty")
        os.replace(temporary_name, output)
        temporary_name = None
        return count
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    args = parser().parse_args()
    if not args.output and not args.trace_output:
        print("error: at least one of --output or --trace-output must be provided", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE

    events_target = args.output
    temp_events_path: Path | None = None

    try:
        if events_target is None:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
            temp_file.close()
            temp_events_path = Path(temp_file.name)
            events_target = temp_events_path

        count = write_events(args.input, args.input_format, events_target, args.force)
        print(f"extracted {count} detailed SBI HTTP/2 event(s)")

        if args.trace_output:
            trace_count = write_projection(events_target, args.trace_output, args.force)
            print(f"projected {trace_count} trace event(s)")

        return 0
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return EXIT_TOOL_UNAVAILABLE
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return EXIT_TSHARK_FAILURE
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    finally:
        if temp_events_path and temp_events_path.exists():
            temp_events_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
