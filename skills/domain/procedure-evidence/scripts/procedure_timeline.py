#!/usr/bin/env python3
"""Render a procedure evidence timeline from stage evidence records.

The timeline shows ordered stages with observed and missing evidence.
It is an evidence listing, not a verdict: it never outputs SUCCESS,
FAILED, or ROOT_CAUSE, and missing evidence is never converted into an
outcome.
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
    EXIT_NO_RECORDS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    load_records,
    render_json,
    render_text,
    timeline_entries,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("input", type=Path, help="procedure evidence JSONL (one stage record per line)")
    result.add_argument("--format", choices=("text", "json"), default="text")
    result.add_argument("--output", type=Path, help="write instead of stdout; existing files are refused without --force")
    result.add_argument("--force", action="store_true", help="explicitly replace an existing output file")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        records = load_records(args.input)
        entries = timeline_entries(records)
        rendered = render_text(entries) if args.format == "text" else render_json(entries)
        if args.output is None:
            sys.stdout.write(rendered)
        else:
            if args.input.resolve() == args.output.resolve():
                raise OSError("timeline output must not replace the input artifact")
            if args.output.exists() and not args.force:
                raise OSError(f"output already exists: {args.output}; use --force to replace it")
            if not args.output.parent.is_dir():
                raise OSError(f"output directory does not exist: {args.output.parent}")
            temporary_name: str | None = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=args.output.parent, prefix=f".{args.output.name}.", suffix=".tmp") as temporary:
                    temporary_name = temporary.name
                    temporary.write(rendered)
                os.replace(temporary_name, args.output)
                temporary_name = None
            finally:
                if temporary_name:
                    Path(temporary_name).unlink(missing_ok=True)
            print(f"wrote timeline for {len(entries)} stage(s) to {args.output.name}")
    except InputError as exc:
        message = str(exc)
        if "no procedure evidence records" in message:
            print(f"input error: {message}", file=sys.stderr)
            return EXIT_NO_RECORDS
        print(f"input error: {message}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
