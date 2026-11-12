#!/usr/bin/env python3
"""Audit already-published EPC artifacts with a read-only evidence ledger.

Consumes the accepted EPC session-identity, bearer-lifecycle and
release-narrative analyses plus, optionally, the accepted EPC S1-U observation,
the detailed GTPv2-C events and the detailed GTP-U events. It never decodes a
capture, never rebuilds a correlation, never re-derives identity and never
changes a producer count. Unresolved audit findings still produce a usable JSON
document, so a finding is inspectable instead of aborting the run.

Exit codes:
  0  audit ledger written with at least one relationship record
  5  malformed input, or a required source document missing or unusable
  6  ledger written but no published relationship could be audited
  7  output failure, including a refused overwrite or a path alias
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_evidence_audit_model import (
    CATEGORY_SOURCE_ARTIFACT,
    EXIT_MALFORMED_INPUT,
    EXIT_NO_SUBJECTS,
    EXIT_OUTPUT_FAILURE,
    AuditInputError,
    InputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)
from epc_evidence_audit_report import render_report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--session-identity",
        type=Path,
        required=True,
        help="accepted EPC session-identity analysis JSON",
    )
    result.add_argument(
        "--lifecycle",
        type=Path,
        required=True,
        help="accepted EPC bearer-lifecycle analysis JSON",
    )
    result.add_argument(
        "--release-narrative",
        type=Path,
        required=True,
        help="accepted EPC release-narrative analysis JSON",
    )
    result.add_argument("--s1u", type=Path, help="accepted EPC S1-U observation JSON")
    result.add_argument(
        "--gtpv2", type=Path, help="optional detailed GTPv2-C event JSONL for anchor audits"
    )
    result.add_argument(
        "--gtpu", type=Path, help="optional detailed GTP-U event JSONL for frame audits"
    )
    result.add_argument("--output", type=Path, required=True, help="audit ledger JSON destination")
    result.add_argument("--report", type=Path, help="optional audit text report destination")
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
            "w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            newline="\n",
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
        for path in (
            args.session_identity,
            args.lifecycle,
            args.release_narrative,
            args.s1u,
            args.gtpv2,
            args.gtpu,
        )
        if path is not None
    ]
    if args.report is not None and args.report.resolve() == args.output.resolve():
        print("output error: the report and the ledger must be different files", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    try:
        identity = read_json(args.session_identity)
        lifecycle = read_json(args.lifecycle)
        narrative = read_json(args.release_narrative)
        s1u = read_json(args.s1u) if args.s1u is not None else None
        gtpv2_events = read_jsonl(args.gtpv2) if args.gtpv2 is not None else None
        gtpu_events = read_jsonl(args.gtpu) if args.gtpu is not None else None
        analysis = analyze(
            identity,
            lifecycle,
            narrative,
            s1u=s1u,
            gtpv2_events=gtpv2_events,
            gtpu_events=gtpu_events,
            provenance={
                "session_identity": safe_name(args.session_identity),
                "lifecycle": safe_name(args.lifecycle),
                "release_narrative": safe_name(args.release_narrative),
                "s1u_observation": safe_name(args.s1u) if args.s1u else None,
                "gtpv2_events": safe_name(args.gtpv2) if args.gtpv2 else None,
                "gtpv2_event_count": len(gtpv2_events) if gtpv2_events is not None else None,
                "gtpu_events": safe_name(args.gtpu) if args.gtpu else None,
                "gtpu_event_count": len(gtpu_events) if gtpu_events is not None else None,
            },
        )
        _check(sources, args.output, args.force)
        if args.report is not None:
            _check(sources, args.report, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.report is not None:
            _write(args.report, render_report(analysis))
            print(f"wrote evidence-audit report to {args.report.name}")
        summary = analysis["audit_summary"]
        print(
            f"audited {analysis['source_artifact_count']} source artifact(s) into "
            f"{analysis['audit_record_count']} audit record(s): {summary['overall_status']} "
            f"({summary['inconsistent_count']} inconsistent, {summary['ambiguous_count']} "
            f"ambiguous, {summary['source_truncated_count']} truncated, "
            f"{summary['not_independently_verifiable_count']} not independently verifiable) to "
            f"{args.output.name}"
        )
        relationship_records = sum(
            1
            for record in analysis["audit_records"]
            if record.get("audit_category") != CATEGORY_SOURCE_ARTIFACT
        )
        return 0 if relationship_records else EXIT_NO_SUBJECTS
    except (AuditInputError, InputError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())