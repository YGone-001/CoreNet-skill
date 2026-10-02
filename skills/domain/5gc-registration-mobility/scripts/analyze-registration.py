#!/usr/bin/env python3
"""Analyze 5GC registration/mobility procedure evidence from lower-layer events.

Loads structured NGAP events, NAS-5GS events, and optionally
cross-protocol-evidence correlation groups; forms evidence-safe procedure
instances; evaluates the conditional registration procedure model; and
emits deterministic output:

- --stage-output: generic procedure-evidence stage JSONL
- --output: bounded analysis summary JSON

The analyzer decodes no packets, requires no subscriber identity, and
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
from procedure_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    ANALYSIS_VERSION,
    PROCEDURE_FAMILY,
    InputError,
    analyze,
    load_correlation_groups,
    load_nas_events,
    load_ngap_events,
    sanitize_output,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ngap", type=Path, action="append", default=[], help="NGAP detailed event JSONL; repeatable")
    result.add_argument("--nas", type=Path, action="append", default=[], help="NAS-5GS detailed event JSONL; repeatable")
    result.add_argument("--correlation", type=Path, action="append", default=[], help="cross-protocol-evidence correlation-event JSONL; repeatable")
    result.add_argument("--output", type=Path, required=True, help="analysis summary JSON destination")
    result.add_argument("--stage-output", type=Path, help="generic procedure-evidence stage JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return result


def _write_atomic(path: Path, payload: str) -> None:
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def _refuse_replacement(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.ngap and not args.nas:
        print("no input events requested; pass --ngap and/or --nas", file=sys.stderr)
        return EXIT_NO_EVENTS
    try:
        _refuse_replacement(args.output, args.force)
        if args.stage_output is not None:
            _refuse_replacement(args.stage_output, args.force)
            if args.stage_output.resolve() in {args.output.resolve()}:
                raise OSError("stage output must differ from the analysis output")

        ngap_events = []
        for path in args.ngap:
            ngap_events.extend(load_ngap_events(path))
        nas_events = []
        for path in args.nas:
            nas_events.extend(load_nas_events(path))
        correlation_groups = []
        for path in args.correlation:
            correlation_groups.extend(load_correlation_groups(path))
        if not ngap_events and not nas_events:
            raise InputError("no input events found")

        rules_dir = Path(__file__).resolve().parents[1] / "rules"
        result = analyze(ngap_events, nas_events, correlation_groups, rules_dir)
        summary = {
            "analysis_version": ANALYSIS_VERSION,
            "procedure_family": PROCEDURE_FAMILY,
            "analyses": result["analyses"],
            "unbound_records": result["unbound_records"],
            "correlation_conflicts": result["correlation_conflicts"],
        }
        sanitize_output(summary)
        _write_atomic(args.output, json.dumps(sanitize_output(summary), sort_keys=True, indent=2) + "\n")
        count = 0
        if args.stage_output is not None:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.stage_output.parent, prefix=f".{args.stage_output.name}.", suffix=".tmp") as temporary:
                for record in result["stage_records"] + result["unbound_records"]:
                    temporary.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                    count += 1
                staged = temporary.name
            os.replace(staged, args.stage_output)
        print(f"analyzed {len(result['analyses'])} procedure instance(s), {len(result['unbound_records'])} unbound record(s)")
        if args.stage_output is not None:
            print(f"wrote {count} stage record(s) to {args.stage_output.name}")
    except InputError as exc:
        message = str(exc)
        if "no input events" in message:
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
