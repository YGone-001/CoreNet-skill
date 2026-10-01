#!/usr/bin/env python3
"""Extract protocol-neutral trace events from a capture or tshark fields JSONL."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pcap_normalize import EXIT_MALFORMED_INPUT, EXIT_NO_FRAMES, EXIT_OUTPUT_FAILURE, InputError, ToolUnavailable, TsharkError, normalize_record, records_for_input, safe_capture_name


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="PCAP/PCAPNG capture or tshark fields JSONL")
    result.add_argument("--input-format", choices=("auto", "capture", "fields-jsonl"), default="auto")
    result.add_argument("--output", type=Path, required=True, help="destination JSON Lines file")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
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
                event, _metadata = normalize_record(record, capture_file)
                temporary.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                count += 1
        if count == 0:
            raise InputError("input contains no frames")
        os.replace(temporary_name, output)
        temporary_name = None
        return count
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        count = write_events(args.input, args.input_format, args.output, args.force)
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return 3
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return 4
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_NO_FRAMES if str(exc) == "input contains no frames" else EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(f"wrote {count} normalized event(s) to {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
