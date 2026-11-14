#!/usr/bin/env python3
"""Build the bounded EPC Dedicated Bearer cross-layer evidence timeline.

The producer reads the accepted Dedicated Bearer control artifact and optional
NAS-EPS/S1AP event JSONL streams. It does not decode a capture, re-correlate
GTPv2-C transactions, or infer a bearer activation outcome.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_dedicated_bearer_timeline_model import (  # noqa: E402
    EXIT_MALFORMED_INPUT,
    EXIT_OUTPUT_FAILURE,
    InputError,
    build_timeline,
    read_json,
    read_jsonl,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--control", type=Path, required=True, help="accepted control artifact")
    result.add_argument("--nas-events", type=Path, help="NAS-EPS detailed event JSONL")
    result.add_argument("--s1ap-events", type=Path, help="S1AP detailed event JSONL")
    result.add_argument("--output", type=Path, required=True, help="timeline artifact destination")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"timeline output already exists: {args.output}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        control = read_json(args.control)
        nas_events = read_jsonl(args.nas_events) if args.nas_events is not None else []
        s1ap_events = read_jsonl(args.s1ap_events) if args.s1ap_events is not None else []
        timeline = build_timeline(
            control,
            nas_events,
            s1ap_events,
            control_path=args.control,
            nas_path=args.nas_events,
            s1ap_path=args.s1ap_events,
        )
    except InputError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(timeline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        print(f"output failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(
        "epc-dedicated-bearer-timeline: "
        f"{timeline['execution_status']} ({timeline['timeline_entry_count']} entries) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())