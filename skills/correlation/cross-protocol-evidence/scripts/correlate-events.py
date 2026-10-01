#!/usr/bin/env python3
"""Correlate NGAP and NAS-5GS detailed events into evidence groups.

Consumes already-extracted protocol events and joins them by capture
provenance only. Produces deterministic correlation-event JSONL; it
never decodes protocols, never correlates subscribers or sessions, and
never issues success, failure, or root-cause verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from correlate_events import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    correlate,
    load_events,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ngap-events", type=Path, action="append", default=[], help="NGAP detailed event JSONL; repeatable")
    result.add_argument("--nas-events", type=Path, action="append", default=[], help="NAS-5GS detailed event JSONL; repeatable")
    result.add_argument("--window-seconds", type=float, default=None, help="bounded timestamp window for MEDIUM joins (default 1.0)")
    result.add_argument("--output", type=Path, required=True, help="correlation-event JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def write_groups(ngap_paths: list[Path], nas_paths: list[Path], output: Path, force: bool, window: float | None) -> int:
    if output.exists() and not force:
        raise OSError(f"output already exists: {output}; use --force to replace it")
    if not output.parent.is_dir():
        raise OSError(f"output directory does not exist: {output.parent}")
    ngap_events = []
    for path in ngap_paths:
        ngap_events.extend(load_events(path, "NGAP"))
    nas_events = []
    for path in nas_paths:
        nas_events.extend(load_events(path, "NAS-5GS"))
    if not ngap_events and not nas_events:
        raise InputError("no input events provided")
    groups = correlate(ngap_events, nas_events, window)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=output.parent, prefix=f".{output.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            for group in groups:
                temporary.write(json.dumps(group, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary_name, output)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
    return len(groups)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        count = write_groups(args.ngap_events, args.nas_events, args.output, args.force, args.window_seconds)
    except InputError as exc:
        message = str(exc)
        if "no input events" in message:
            print(f"input error: {message}", file=sys.stderr)
            return EXIT_NO_EVENTS
        print(f"input error: {message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(f"correlated into {count} evidence group(s) -> {args.output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
