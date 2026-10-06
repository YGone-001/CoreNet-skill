#!/usr/bin/env python3
"""CLI driver for 5GC failure-boundary orchestration.

Composes already-produced Domain analysis JSON:
- 5gc-registration-mobility analysis summaries (--registration, repeatable)
- 5gc-pdu-session analysis summaries (--pdu-session, repeatable)
- 5gc-handover-mobility analysis summaries (--handover-mobility, repeatable)
or a directory (--input-dir) whose *.json files are auto-detected through the
authoritative JSON discriminators (analysis_name / procedure_family /
procedure_name); the documented file naming is only a fallback for files
without a recognizable discriminator, and a misleading filename never
overrides an authoritative discriminator.

Outputs:
- --output: bounded failure-boundary analysis summary JSON
- --report: text investigation report
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failure_boundary_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_INPUT,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
)


def parser() -> argparse.ArgumentParser:
    res = argparse.ArgumentParser(description=__doc__)
    res.add_argument("--registration", type=Path, action="append", default=[],
                     help="5gc-registration-mobility analysis summary JSON; repeatable")
    res.add_argument("--pdu-session", type=Path, action="append", default=[],
                     help="5gc-pdu-session analysis summary JSON; repeatable")
    res.add_argument("--handover-mobility", type=Path, action="append", default=[],
                     help="5gc-handover-mobility analysis summary JSON; repeatable")
    res.add_argument("--input-dir", type=Path,
                     help="directory containing Domain analysis JSON files, auto-detected through the "
                          "authoritative JSON discriminators")
    res.add_argument("--output", type=Path, required=True, help="analysis summary JSON destination")
    res.add_argument("--report", type=Path, help="text investigation report destination")
    res.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return res


def _discriminate(doc: object) -> str | None:
    """Return the Domain kind for an already-parsed analysis document."""
    if not isinstance(doc, dict):
        return None
    if doc.get("analysis_name") == "5gc-handover-mobility" or doc.get("procedure_family") == "5gc-handover-mobility":
        return "5gc-handover-mobility"
    if doc.get("procedure_family") == "5gc-registration-mobility":
        return "5gc-registration-mobility"
    if doc.get("procedure_name") == "5gc-pdu-session":
        return "5gc-pdu-session"
    if doc.get("analysis_name") == "5gc-failure-boundary":
        return "5gc-failure-boundary"
    return None


def _collect(args: argparse.Namespace) -> tuple[list[Path], list[Path], list[Path]]:
    registration = list(args.registration)
    pdu_session = list(args.pdu_session)
    handover_mobility = list(args.handover_mobility)
    if args.input_dir is not None:
        if not args.input_dir.is_dir():
            raise InputError(f"input-dir does not exist: {args.input_dir}")
        for path in sorted(args.input_dir.glob("*.json")):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON in {path.name}: {exc.msg}") from exc
            kind = _discriminate(doc)
            if kind is None:
                # Fallback to the documented naming only when the JSON carries
                # no authoritative discriminator; a recognized discriminator
                # always wins over a misleading filename.
                name = path.name.lower()
                if "registration" in name:
                    kind = "5gc-registration-mobility"
                elif "pdu" in name:
                    kind = "5gc-pdu-session"
                elif "handover" in name or "mobility" in name:
                    kind = "5gc-handover-mobility"
            if kind == "5gc-registration-mobility":
                registration.append(path)
            elif kind == "5gc-pdu-session":
                pdu_session.append(path)
            elif kind == "5gc-handover-mobility":
                handover_mobility.append(path)
            else:
                raise InputError(
                    f"cannot determine the Domain of {path.name}; the file carries no authoritative "
                    "analysis discriminator and the name does not match a documented Domain input"
                )
    return registration, pdu_session, handover_mobility


def _write_atomic(path: Path, payload: str) -> None:
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp") as tmp:
            temp_name = tmp.name
            tmp.write(payload)
        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)


def _refuse(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _refuse(args.output, args.force)
        if args.report is not None:
            _refuse(args.report, args.force)
        registration, pdu_session, handover_mobility = _collect(args)
        summary = analyze(registration, pdu_session, handover_mobility)
        _write_atomic(args.output, json.dumps(summary, indent=2, sort_keys=True) + "\n")
        if args.report is not None:
            from failure_boundary_report import render_text
            _write_atomic(args.report, render_text(summary))
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"I/O error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except Exception as exc:  # noqa: BLE001 - fail loudly with exit code
        print(f"unexpected analysis failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    sys.exit(main())
