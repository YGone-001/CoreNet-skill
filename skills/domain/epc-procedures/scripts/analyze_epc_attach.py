#!/usr/bin/env python3
"""Analyze bounded EPS Attach procedure evidence from accepted S1AP and NAS-EPS events.

Consumes the detailed event JSONL produced by the `s1ap` and `nas-eps` Protocol
Skills and emits a procedure-instance analysis plus an optional stage timeline.
No protocol decoding, no subscriber identity, no bearer or PDN success claim, and
no global first-abnormal boundary selection.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_attach_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_INSTANCES,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    load_inputs,
    safe_name,
    stage_rows,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--s1ap", type=Path, required=True, help="detailed S1AP event JSONL")
    result.add_argument("--nas", type=Path, required=True, help="detailed NAS-EPS event JSONL")
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument("--stage-output", type=Path, help="optional stage timeline JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _check(source: Path, destination: Path, force: bool) -> None:
    if source.resolve() == destination.resolve():
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
            prefix=f".{path.name}.", suffix=".tmp",
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
        s1ap_events, nas_events = load_inputs(args.s1ap, args.nas)
        analysis = analyze(s1ap_events, nas_events, safe_name(args.s1ap), safe_name(args.nas))
        _check(args.s1ap, args.output, args.force)
        if args.stage_output is not None:
            _check(args.nas, args.stage_output, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.stage_output is not None:
            rows = stage_rows(analysis)
            _write(
                args.stage_output,
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            )
            print(f"wrote {len(rows)} stage record(s) to {args.stage_output.name}")
        print(
            f"wrote EPS Attach analysis for {analysis['instance_count']} procedure instance(s) "
            f"to {args.output.name}"
        )
        return 0 if analysis["instance_count"] else EXIT_NO_INSTANCES
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
