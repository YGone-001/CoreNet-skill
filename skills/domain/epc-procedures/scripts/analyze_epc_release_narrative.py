#!/usr/bin/env python3
"""Analyze bounded EPC session-level release narratives and temporal evidence.

Consumes the accepted EPC session-identity and bearer-lifecycle analyses plus,
optionally, the accepted EPC S1-U observation, the detailed GTPv2-C events and
the detailed GTP-U events. It never decodes a capture, never rebuilds a
transaction correlation, never re-derives session identity, never changes a
packet or octet attribution and never publishes subscriber identity.

Exit codes:
  0  narrative analysis written with at least one release narrative
  5  malformed input, or a required source document missing or inconsistent
  6  analysis written but no release narrative could be constructed
  7  output failure, including a refused overwrite
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_release_narrative_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_SUBJECTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    NarrativeInputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)
from epc_release_narrative_report import render_report


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
    result.add_argument("--s1u", type=Path, help="accepted EPC S1-U observation JSON")
    result.add_argument(
        "--gtpv2",
        type=Path,
        help="optional detailed GTPv2-C event JSONL for anchor validation only",
    )
    result.add_argument(
        "--gtpu",
        type=Path,
        help="optional detailed GTP-U event JSONL for frame-level temporal evidence",
    )
    result.add_argument("--output", type=Path, required=True, help="narrative analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional narrative text report destination")
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
        for path in (args.session_identity, args.lifecycle, args.s1u, args.gtpv2, args.gtpu)
        if path is not None
    ]
    try:
        identity = read_json(args.session_identity)
        lifecycle = read_json(args.lifecycle)
        s1u = read_json(args.s1u) if args.s1u is not None else None
        gtpv2_events = read_jsonl(args.gtpv2) if args.gtpv2 is not None else None
        gtpu_events = read_jsonl(args.gtpu) if args.gtpu is not None else None
        analysis = analyze(
            identity,
            lifecycle,
            s1u=s1u,
            gtpv2_events=gtpv2_events,
            gtpu_events=gtpu_events,
            provenance={
                "session_identity": safe_name(args.session_identity),
                "lifecycle": safe_name(args.lifecycle),
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
            print(f"wrote release-narrative report to {args.report.name}")
        print(
            f"wrote EPC release narrative for {analysis['narrative_subject_count']} narrative "
            f"subject(s), {analysis['release_narrative_count']} release narrative(s) and "
            f"{analysis['temporal_observation_count']} temporal observation(s) to "
            f"{args.output.name}"
        )
        return 0 if analysis["release_narrative_count"] else EXIT_NO_SUBJECTS
    except (NarrativeInputError, InputError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
