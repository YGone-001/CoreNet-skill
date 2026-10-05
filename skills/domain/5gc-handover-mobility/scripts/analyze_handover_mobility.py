#!/usr/bin/env python3
"""Analyze bounded 5GC handover/path-switch mobility evidence.

Consumes already-extracted NGAP, PFCP, GTP-U, and SBI-HTTP2 detailed event
JSONL plus an optional 5gc-pdu-session analysis summary, and writes the
bounded mobility analysis summary JSON (and optionally generic
procedure-evidence stage records). It performs no protocol decoding and
never emits success, failure, or root-cause verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mobility_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    build_stage_records,
    load_gtpu_events,
    load_ngap_events,
    load_pfcp_events,
    load_pdu_session_context,
    load_sbi_events,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--ngap", type=Path, action="append", default=[], help="NGAP detailed event JSONL; repeatable")
    result.add_argument("--pfcp", type=Path, action="append", default=[], help="PFCP detailed event JSONL; repeatable")
    result.add_argument("--gtpu", type=Path, action="append", default=[], help="GTP-U detailed event JSONL; repeatable")
    result.add_argument("--sbi", type=Path, action="append", default=[], help="SBI-HTTP2 detailed event JSONL; repeatable")
    result.add_argument("--pdu-session", type=Path, dest="pdu_session", help="optional 5gc-pdu-session analysis summary JSON (>=0.4.0) for lifecycle and N4/N3 context")
    result.add_argument("--output", type=Path, required=True, help="analysis summary JSON destination")
    result.add_argument("--stage-output", type=Path, help="generic procedure-evidence stage JSONL destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing output files")
    return result


def _write_json(path: Path, document: object, force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            temporary.write(json.dumps(document, sort_keys=True, indent=2) + "\n")
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def _write_jsonl(path: Path, records: list[dict[str, object]], force: bool) -> None:
    if path.exists() and not force:
        raise OSError(f"output already exists: {path}; use --force to replace it")
    if not path.parent.is_dir():
        raise OSError(f"output directory does not exist: {path.parent}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp") as temporary:
            temporary_name = temporary.name
            for record in records:
                temporary.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.output.resolve() in {path.resolve() for path in args.ngap + args.pfcp + args.gtpu + args.sbi}:
        print("output must not replace an input artifact", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        ngap_events: list[dict[str, object]] = []
        for path in args.ngap:
            ngap_events.extend(load_ngap_events(path))
        pfcp_events: list[dict[str, object]] = []
        for path in args.pfcp:
            pfcp_events.extend(load_pfcp_events(path))
        gtpu_events: list[dict[str, object]] = []
        for path in args.gtpu:
            gtpu_events.extend(load_gtpu_events(path))
        sbi_events: list[dict[str, object]] = []
        for path in args.sbi:
            sbi_events.extend(load_sbi_events(path))
        pdu_session_context = load_pdu_session_context(args.pdu_session) if args.pdu_session else None

        if not ngap_events and not pfcp_events and not gtpu_events and not sbi_events:
            print("no evidence files supplied", file=sys.stderr)
            return EXIT_NO_EVENTS

        document = analyze(ngap_events, pfcp_events, gtpu_events, sbi_events, pdu_session_context)
        _write_json(args.output, document, args.force)
        print(
            f"wrote analysis with {len(document['handover_attempts'])} handover attempt(s) and "
            f"{len(document['path_switch_attempts'])} path-switch attempt(s) to {args.output.name}"
        )
        if args.stage_output is not None:
            records = build_stage_records(document)
            _write_jsonl(args.stage_output, records, args.force)
            print(f"wrote {len(records)} procedure-evidence stage record(s) to {args.stage_output.name}")
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
