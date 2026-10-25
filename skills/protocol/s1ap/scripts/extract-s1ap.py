#!/usr/bin/env python3
"""Extract bounded S1AP semantic events from a capture or structured JSONL.

Outputs detailed S1AP JSONL events, an optional shared trace-event projection
and an optional UE-context correlation summary. NAS-PDU payloads are never
decoded or republished; only presence and length are retained.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s1ap_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    EXIT_TSHARK_FAILURE,
    EXIT_TOOL_UNAVAILABLE,
    InputError,
    TsharkError,
    ToolUnavailable,
    build_correlation,
    erab_index_for_capture,
    input_kind,
    normalize_record,
    project_trace_event,
    records_for_input,
    safe_capture_name,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="PCAP/PCAPNG capture or structured S1AP fields JSONL")
    result.add_argument("--input-format", choices=("auto", "capture", "fields-jsonl"), default="auto")
    result.add_argument("--output", type=Path, help="detailed S1AP event JSONL destination")
    result.add_argument("--trace-output", type=Path, help="shared trace-event JSONL projection destination")
    result.add_argument("--correlation-output", type=Path, help="UE-context correlation summary JSON destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return result


def _check_destination(source: Path, destination: Path, force: bool) -> None:
    if source.resolve() == destination.resolve():
        raise OSError("output must not replace the input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def _write_jsonl(destination: Path, rows: list[dict[str, object]]) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp",
        ) as temporary:
            temporary_name = temporary.name
            for row in rows:
                temporary.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def _write_json(destination: Path, payload: object) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp",
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(temporary_name, destination)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def collect_events(input_path: Path, input_format: str) -> list[dict[str, object]]:
    records, _version = records_for_input(input_path, input_format)
    capture_file = safe_capture_name(input_path)
    # A capture is dissected to PDML as well, because only the dissector tree
    # proves which E-RAB identity, QoS value and tunnel endpoint form one item.
    if input_kind(input_path, input_format) == "capture":
        erab_index, nas_frames = erab_index_for_capture(input_path)
    else:
        erab_index, nas_frames = None, None
    events = [normalize_record(record, capture_file, erab_index, nas_frames) for record in records]
    if not events:
        raise InputError("input contains no S1AP records")
    return events


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.output is None and args.trace_output is None and args.correlation_output is None:
        print("no destination requested; pass --output, --trace-output and/or --correlation-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        events = collect_events(args.input, args.input_format)
        if args.output is not None:
            _check_destination(args.input, args.output, args.force)
            _write_jsonl(args.output, events)
            print(f"wrote {len(events)} detailed S1AP event(s) to {args.output.name}")
        if args.trace_output is not None:
            _check_destination(args.input, args.trace_output, args.force)
            _write_jsonl(args.trace_output, [project_trace_event(event) for event in events])
            print(f"wrote {len(events)} trace-event projection(s) to {args.trace_output.name}")
        if args.correlation_output is not None:
            _check_destination(args.input, args.correlation_output, args.force)
            _write_json(args.correlation_output, build_correlation(events))
            print(f"wrote UE-context correlation summary to {args.correlation_output.name}")
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return EXIT_TOOL_UNAVAILABLE
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return EXIT_TSHARK_FAILURE
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_EVENTS if "no S1AP records" in str(exc) else EXIT_MALFORMED_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
