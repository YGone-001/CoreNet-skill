#!/usr/bin/env python3
"""CLI driver for bounded EPC failure-boundary orchestration.

Consumes accepted EPC Domain analyses only:

- `--attach`: an `epc-procedures` EPS Attach analysis JSON (repeatable)
- `--session`: an `epc-procedures` EPC session-control analysis JSON (repeatable)
- `--default-bearer`: an `epc-procedures` EPS default-bearer analysis JSON (repeatable)

At least one input is required. A missing optional Domain is not an error. A
supplied but unusable Domain artifact fails visibly. No raw protocol event input
is accepted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_boundary_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_INPUT,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
)
from epc_boundary_report import render_text


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--attach",
        type=Path,
        action="append",
        default=[],
        help="epc-procedures EPS Attach analysis JSON; repeatable",
    )
    result.add_argument(
        "--session",
        type=Path,
        action="append",
        default=[],
        help="epc-procedures EPC session-control analysis JSON; repeatable",
    )
    result.add_argument(
        "--default-bearer",
        type=Path,
        action="append",
        default=[],
        help="epc-procedures EPS default-bearer analysis JSON; repeatable",
    )
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument("--report", type=Path, help="text report destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return result


def _refuse(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")


def _write_atomic(path: Path, payload: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", newline="\n",
        ) as handle:
            temporary = handle.name
            handle.write(payload)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.attach and not args.session and not args.default_bearer:
        print(
            "input error: at least one of --attach, --session or --default-bearer is required",
            file=sys.stderr,
        )
        return EXIT_NO_INPUT
    try:
        _refuse(args.output, args.force)
        if args.report is not None:
            _refuse(args.report, args.force)
        summary = analyze(list(args.attach), list(args.session), list(args.default_bearer))
        _write_atomic(args.output, json.dumps(summary, indent=2, sort_keys=True) + "\n")
        if args.report is not None:
            _write_atomic(args.report, render_text(summary))
        print(
            f"wrote EPC failure-boundary analysis for "
            f"{len(summary['diagnostic_groups'])} diagnostic group(s) to {args.output.name}"
        )
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
