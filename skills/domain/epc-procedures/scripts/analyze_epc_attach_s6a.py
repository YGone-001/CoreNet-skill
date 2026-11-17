#!/usr/bin/env python3
"""Combine accepted EPS Attach and Diameter S6a/S6d evidence.

The joint output preserves both producers' evidence and explicitly refuses to
invent a per-UE cross-protocol identity when privacy-safe evidence cannot prove it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_attach_s6a_model import InputError, analyze, load_json  # noqa: E402
from epc_attach_s6a_report import render_report  # noqa: E402

EXIT_INVALID_INPUT = 2
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--attach", type=Path, required=True, help="accepted EPC Attach analysis JSON")
    result.add_argument("--diameter-epc", type=Path, required=True, help="accepted Diameter EPC analysis JSON")
    result.add_argument("--output", type=Path, required=True, help="joint analysis JSON destination")
    result.add_argument("--report", type=Path, help="human-readable joint report destination")
    result.add_argument("--capture", type=Path, help="optional coordinated capture for verified provenance")
    result.add_argument(
        "--run-manifest",
        type=Path,
        help="optional coordinated-run manifest recording producer invocations and digests",
    )
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _check(source: Path, destination: Path, force: bool) -> None:
    if destination.resolve() == source.resolve():
        raise OSError("output must not replace an input artifact")
    if destination.exists() and not force:
        raise OSError(f"output already exists: {destination}; use --force to replace it")
    if not destination.parent.is_dir():
        raise OSError(f"output directory does not exist: {destination.parent}")


def _write(path: Path, text: str) -> None:
    temporary_name = None
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
        attach = load_json(args.attach)
        diameter = load_json(args.diameter_epc)
        run_manifest = load_json(args.run_manifest) if args.run_manifest is not None else None
        document = analyze(
            attach,
            diameter,
            attach_path=args.attach,
            diameter_path=args.diameter_epc,
            capture=args.capture,
            run_manifest=run_manifest,
            run_manifest_path=args.run_manifest,
        )
        _check(args.attach, args.output, args.force)
        if args.report is not None:
            _check(args.diameter_epc, args.report, args.force)
        _write(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(
            f"wrote joint analysis for {len(document['attach_inventory'])} Attach instance(s) "
            f"and {len(document['diameter_inventory'])} Diameter observation(s) to {args.output.name}"
        )
        if args.report is not None:
            _write(args.report, render_report(document))
            print(f"wrote joint report to {args.report.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_INVALID_INPUT
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())