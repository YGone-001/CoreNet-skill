#!/usr/bin/env python3
"""Analyze bounded EPC bearer lifecycle-generation evidence.

Consumes the GTPv2-C detailed events, their accepted transaction correlation and
the accepted EPC session-control, default-bearer and S1-U observation documents.
Detailed GTP-U events are optional and only enable frame-level packet
attribution.

It never decodes a capture, never parses protocol bytes, never rebuilds
request/response matching from timestamps and never publishes subscriber
identity.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_bearer_lifecycle_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_SUBJECTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)


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
    result.add_argument("--s1u", type=Path, help="accepted EPC S1-U observation JSON")
    result.add_argument("--gtpu", type=Path, help="detailed GTP-U event JSONL for frame-level attribution")
    result.add_argument("--output", type=Path, required=True, help="lifecycle analysis JSON destination")
    result.add_argument(
        "--timeline-output",
        type=Path,
        help="optional generation timeline JSONL destination",
    )
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


def timeline_rows(analysis: dict) -> list[dict]:
    rows: list[dict] = []
    for subject in analysis.get("lifecycle_subjects") or []:
        if not isinstance(subject, dict):
            continue
        rows.append(
            {
                "generation_reference": subject.get("generation_reference"),
                "capture_file": subject.get("capture_file"),
                "receiving_endpoint_role": subject.get("receiving_endpoint_role"),
                "reviewed_interface_type": subject.get("reviewed_interface_type"),
                "generation_state": subject.get("generation_state"),
                "observation_window": subject.get("observation_window"),
                "observations": subject.get("observations"),
                "advertisement_family_references": subject.get("advertisement_family_references"),
            }
        )
    rows.sort(
        key=lambda row: (
            (row["observation_window"] or {}).get("start_frame", 1 << 30),
            str(row["generation_reference"]),
        )
    )
    return rows


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    sources = [
        path
        for path in (args.gtpv2, args.transactions, args.session, args.default_bearer, args.s1u, args.gtpu)
        if path is not None
    ]
    try:
        events = read_jsonl(args.gtpv2)
        transactions = read_json(args.transactions)
        session = read_json(args.session) if args.session is not None else None
        default_bearer = read_json(args.default_bearer) if args.default_bearer is not None else None
        s1u = read_json(args.s1u) if args.s1u is not None else None
        gtpu = read_jsonl(args.gtpu) if args.gtpu is not None else []
        analysis = analyze(
            events,
            transactions=transactions,
            session_analysis=session,
            default_bearer=default_bearer,
            s1u_analysis=s1u,
            gtpu_events=gtpu,
            provenance={
                "gtpv2_events": safe_name(args.gtpv2),
                "gtpv2_event_count": len(events),
                "gtpv2_transactions": safe_name(args.transactions),
                "transaction_count": len(transactions.get("transactions") or []),
                "session_analysis": safe_name(args.session) if args.session else None,
                "default_bearer_analysis": safe_name(args.default_bearer) if args.default_bearer else None,
                "s1u_observation": safe_name(args.s1u) if args.s1u else None,
                "gtpu_events": safe_name(args.gtpu) if args.gtpu else None,
                "gtpu_event_count": len(gtpu),
            },
        )
        _check(sources, args.output, args.force)
        if args.timeline_output is not None:
            _check(sources, args.timeline_output, args.force)
        _write(args.output, json.dumps(analysis, indent=2, sort_keys=True) + "\n")
        if args.timeline_output is not None:
            rows = timeline_rows(analysis)
            _write(
                args.timeline_output,
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            )
            print(f"wrote {len(rows)} generation timeline record(s) to {args.timeline_output.name}")
        accounting = analysis["accounting"]
        print(
            f"wrote EPC bearer lifecycle evidence for {analysis['lifecycle_subject_count']} "
            f"generation(s) and {analysis['advertisement_family_count']} advertisement family(ies); "
            f"attributed {accounting['attributed_g_pdu_count']} of "
            f"{accounting['aggregate_g_pdu_count']} observed G-PDU(s) to {args.output.name}"
        )
        return 0 if analysis["lifecycle_subject_count"] or analysis["advertisement_family_count"] else EXIT_NO_SUBJECTS
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
