#!/usr/bin/env python3
"""Analyze bounded EPC session-control evidence from accepted GTPv2-C output.

Consumes the detailed GTPv2-C events and the protocol-local transaction
correlation produced by the `gtpv2` Protocol Skill. It does not decode a capture,
does not reinterpret GTPv2 binary fields, and never claims PDN-connection,
bearer-service or user-plane success.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_session_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_TRANSACTIONS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    load_inputs,
    procedure_rows,
    safe_name,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gtpv2", type=Path, required=True, help="detailed GTPv2-C event JSONL")
    result.add_argument("--transactions", type=Path, required=True, help="GTPv2-C transaction correlation JSON")
    result.add_argument("--output", type=Path, required=True, help="session-control analysis JSON destination")
    result.add_argument("--timeline-output", type=Path, help="optional procedure timeline JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _check(sources: list[Path], destination: Path, force: bool) -> None:
    resolved = destination.resolve()
    for source in sources:
        if source.resolve() == resolved:
            raise OSError("output must not replace an input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def _write(path: Path, text: str) -> None:
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", newline="\n",
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(text)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        events, document = load_inputs(args.gtpv2, args.transactions)
        analysis = analyze(events, document, safe_name(args.gtpv2), safe_name(args.transactions))
        _check([args.gtpv2, args.transactions], args.output, args.force)
        if args.timeline_output is not None:
            _check([args.gtpv2, args.transactions], args.timeline_output, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.timeline_output is not None:
            rows = procedure_rows(analysis)
            _write(
                args.timeline_output,
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            )
            print(f"wrote {len(rows)} procedure timeline record(s) to {args.timeline_output.name}")
        print(
            f"wrote EPC session-control analysis for "
            f"{analysis['control_plane_subject_count']} subject(s) and "
            f"{analysis['input_provenance']['transaction_count']} transaction(s) to {args.output.name}"
        )
        return 0 if analysis["control_plane_subject_count"] else EXIT_NO_TRANSACTIONS
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
