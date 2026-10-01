#!/usr/bin/env python3
"""Inventory generic metadata from a capture or tshark fields JSONL input."""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

from pcap_normalize import InputError, ToolUnavailable, TsharkError, normalize_record, records_for_input, safe_capture_name


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="PCAP/PCAPNG capture or tshark fields JSONL")
    result.add_argument("--input-format", choices=("auto", "capture", "fields-jsonl"), default="auto")
    result.add_argument("--json", action="store_true", help="emit machine-readable inventory JSON")
    return result


def inventory(input_path: Path, input_format: str) -> dict[str, object]:
    records, tshark = records_for_input(input_path, input_format)
    capture_file = safe_capture_name(input_path)
    first: str | None = None
    last: str | None = None
    count = 0
    families: set[str] = set()
    endpoints: set[tuple[str | None, int | None]] = set()
    transports: set[str] = set()
    dissectors: set[str] = set()
    dissector_names: set[str] = set()
    for record in records:
        event, metadata = normalize_record(record, capture_file)
        timestamp = str(event["timestamp"])
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        count += 1
        families.update(metadata.address_families)
        endpoints.update(metadata.endpoints)
        if metadata.transport:
            transports.add(metadata.transport)
        dissectors.add(metadata.classification)
        dissector_names.update(token for token in metadata.stack.split(":") if token)
    if count == 0:
        raise InputError("input contains no frames")
    duration: str | None = None
    if first and last:
        from datetime import datetime

        duration = str(Decimal(str((datetime.fromisoformat(last.replace("Z", "+00:00")) - datetime.fromisoformat(first.replace("Z", "+00:00"))).total_seconds())).quantize(Decimal("0.000001")))
    return {
        "capture_file": capture_file,
        "frame_count": count,
        "first_timestamp": first,
        "last_timestamp": last,
        "duration_seconds": duration,
        "address_families": sorted(families),
        "endpoints": [{"address": address, "port": port} for address, port in sorted(endpoints, key=lambda item: (item[0] or "", item[1] if item[1] is not None else -1))],
        "transport_protocols": sorted(transports),
        "dissector_protocol_names": sorted(dissector_names),
        "dissector_protocols": sorted(dissectors),
        "truncation_indicators": [],
        "tshark_version": tshark,
        "warnings": (["tshark version is unavailable for pre-extracted JSONL input"] if tshark is None else []) + ["No truncation indicator is extracted by the metadata-only field set."],
    }


def human_readable(data: dict[str, object]) -> str:
    lines = [f"Capture: {data['capture_file']}", f"Frames: {data['frame_count']}", f"Interval: {data['first_timestamp']} to {data['last_timestamp']}", f"Transports: {', '.join(data['transport_protocols']) or 'none'}", f"Observed stack names: {', '.join(data['dissector_protocol_names']) or 'none'}", f"Classifications: {', '.join(data['dissector_protocols']) or 'none'}"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        data = inventory(args.input, args.input_format)
    except ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return 3
    except TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return 4
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 6 if str(exc) == "input contains no frames" else 5
    print(json.dumps(data, sort_keys=True, indent=2) if args.json else human_readable(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
