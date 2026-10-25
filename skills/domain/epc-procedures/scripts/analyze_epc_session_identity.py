#!/usr/bin/env python3
"""Analyze bounded EPC S11<->S5/S8 session-identity bridge evidence.

Consumes the GTPv2-C detailed events, their accepted transaction correlation and
the accepted EPC session-control, default-bearer and bearer-lifecycle documents.
It never decodes a capture, never parses protocol bytes, never rebuilds
request/response matching and never publishes subscriber identity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_session_identity_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_SUBJECTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)
from epc_session_identity_report import render_report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gtpv2", type=Path, required=True, help="GTPv2-C detailed event JSONL")
    result.add_argument(
        "--transactions",
        type=Path,
        required=True,
        help="accepted GTPv2-C transaction correlation JSON",
    )
    result.add_argument("--session", type=Path, help="accepted EPC session-control analysis JSON")
    result.add_argument("--default-bearer", type=Path, help="accepted EPS default-bearer analysis JSON")
    result.add_argument("--lifecycle", type=Path, help="accepted EPC bearer-lifecycle analysis JSON")
    result.add_argument("--output", type=Path, required=True, help="session-identity analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional session-identity text report destination")
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
    sources = [
        path
        for path in (args.gtpv2, args.transactions, args.session, args.default_bearer, args.lifecycle)
        if path is not None
    ]
    try:
        events = read_jsonl(args.gtpv2)
        transactions = read_json(args.transactions)
        session = read_json(args.session) if args.session is not None else None
        default_bearer = read_json(args.default_bearer) if args.default_bearer is not None else None
        lifecycle = read_json(args.lifecycle) if args.lifecycle is not None else None
        analysis = analyze(
            events,
            transactions=transactions,
            session_analysis=session,
            default_bearer=default_bearer,
            lifecycle_analysis=lifecycle,
            provenance={
                "gtpv2_events": safe_name(args.gtpv2),
                "gtpv2_event_count": len(events),
                "gtpv2_transactions": safe_name(args.transactions),
                "transaction_count": len(transactions.get("transactions") or []),
                "session_analysis": safe_name(args.session) if args.session else None,
                "default_bearer_analysis": safe_name(args.default_bearer) if args.default_bearer else None,
                "lifecycle_analysis": safe_name(args.lifecycle) if args.lifecycle else None,
            },
        )
        _check(sources, args.output, args.force)
        if args.report is not None:
            _check(sources, args.report, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.report is not None:
            _write(args.report, render_report(analysis))
            print(f"wrote session-identity report to {args.report.name}")
        print(
            f"wrote EPC session-identity evidence for {analysis['hop_local_context_count']} "
            f"hop-local context(s), {analysis['session_identity_count']} cross-interface session "
            f"identity link(s), {analysis['release_session_binding_count']} release binding(s) "
            f"and {analysis['established_closure_candidate_count']} established closure "
            f"candidate(s) to {args.output.name}"
        )
        populated = (
            analysis["hop_local_context_count"]
            or analysis["release_session_binding_count"]
            or analysis["session_to_generation_count"]
            or analysis["unbound_evidence_count"]
        )
        return 0 if populated else EXIT_NO_SUBJECTS
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
