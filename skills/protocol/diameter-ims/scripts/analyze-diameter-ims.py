#!/usr/bin/env python3
"""Analyze accepted Diameter Core evidence as bounded Cx/Dx application evidence."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diameter_ims_model import (  # noqa: E402
    InputError,
    analyze,
    load_json,
    load_jsonl,
    render_timeline,
    sha256,
)

EXIT_INVALID_INPUT = 2
EXIT_NO_OBSERVATIONS = 3
EXIT_OUTPUT_FAILURE = 6


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True, help="Diameter Core event JSONL")
    parser.add_argument("--transactions", type=Path, required=True, help="Diameter Core transaction JSON")
    parser.add_argument("--output", type=Path, help="Diameter IMS analysis JSON destination")
    parser.add_argument("--timeline-output", type=Path, help="application timeline destination")
    parser.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return parser


def check_destination(source: Path, destination: Path, force: bool) -> None:
    if destination.resolve() == source.resolve():
        raise OSError("output must not replace an input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


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
    args = build_parser().parse_args(argv)
    if args.output is None and args.timeline_output is None:
        print("no destination requested; pass --output and/or --timeline-output", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        events = load_jsonl(args.events)
        transaction_document = load_json(args.transactions)
        if not isinstance(transaction_document, dict):
            raise InputError("transaction input must be a JSON object")
        provenance = {
            "capture_files": sorted({event.get("capture_file") for event in events if event.get("capture_file")}),
            "event_count": len(events),
            "transaction_count": len(transaction_document.get("transactions") or []),
            "events_sha256": sha256(args.events),
            "transactions_sha256": sha256(args.transactions),
        }
        document = analyze(events, transaction_document, input_provenance=provenance)
        if not document["observations"]:
            print("input contains no reviewed Cx/Dx application evidence", file=sys.stderr)
            return EXIT_NO_OBSERVATIONS
        if args.output is not None:
            check_destination(args.transactions, args.output, args.force)
            write_text(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
            print(f"wrote {document['completeness']['observation_count']} observation(s) to {args.output.name}")
        if args.timeline_output is not None:
            check_destination(args.transactions, args.timeline_output, args.force)
            write_text(args.timeline_output, render_timeline(document))
            print(f"wrote timeline to {args.timeline_output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())