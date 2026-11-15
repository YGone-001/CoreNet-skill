#!/usr/bin/env python3
"""Build the bounded EPC Dedicated Bearer control-to-access attribution artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_dedicated_bearer_attribution_model import (  # noqa: E402
    EXIT_MALFORMED_INPUT,
    EXIT_OUTPUT_FAILURE,
    InputError,
    build_attribution,
    read_json,
    read_jsonl,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--control", type=Path, required=True)
    result.add_argument("--session-identity", type=Path, required=True)
    result.add_argument("--gtpv2-events", type=Path)
    result.add_argument("--nas-events", type=Path)
    result.add_argument("--s1ap-events", type=Path)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--force", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.output.exists() and not args.force:
        print(f"attribution output already exists: {args.output}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        control = read_json(args.control)
        identity = read_json(args.session_identity)
        gtpv2_events = read_jsonl(args.gtpv2_events)
        nas_events = read_jsonl(args.nas_events)
        s1ap_events = read_jsonl(args.s1ap_events)
        attribution = build_attribution(
            control,
            identity,
            gtpv2_events,
            nas_events,
            s1ap_events,
            control_path=args.control,
            identity_path=args.session_identity,
            gtpv2_path=args.gtpv2_events,
            nas_path=args.nas_events,
            s1ap_path=args.s1ap_events,
        )
    except InputError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(attribution, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        print(f"output failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    print(
        "epc-dedicated-bearer-attribution: "
        f"{attribution['execution_status']} ({attribution['attribution_entry_count']} entries) -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())