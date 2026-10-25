#!/usr/bin/env python3
"""Analyze bounded EPC S1-U GTP-U observation from accepted lower-layer output.

Consumes the detailed GTP-U events and the directed stream summary produced by
the `gtpu` Protocol Skill, the accepted EPS default-bearer analysis, and
optionally the GTPv2-C events that advertise the SGW-U S1-U endpoint.

It never decodes a capture, never parses a GTP-U header, never publishes inner
packet content, and never claims packet delivery or application reachability.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_s1u_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_STREAMS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    analyze,
    read_json,
    read_jsonl,
    safe_name,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gtpu", type=Path, required=True, help="detailed GTP-U event JSONL")
    result.add_argument("--streams", type=Path, required=True, help="directed GTP-U stream summary JSON")
    result.add_argument("--default-bearer", type=Path, help="accepted EPS default-bearer analysis JSON")
    result.add_argument(
        "--gtpv2",
        type=Path,
        help="GTPv2-C event JSONL, used only for the SGW-U S1-U receiving endpoint",
    )
    result.add_argument("--output", type=Path, required=True, help="S1-U observation JSON destination")
    result.add_argument("--timeline-output", type=Path, help="optional stream timeline JSONL destination")
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
    for stream in analysis.get("stream_observations") or []:
        if not isinstance(stream, dict):
            continue
        rows.append(
            {
                "stream_reference": stream.get("stream_reference"),
                "outer_source": stream.get("outer_source"),
                "outer_destination": stream.get("outer_destination"),
                "teid": stream.get("teid"),
                "direction": stream.get("direction"),
                "user_plane_interface": stream.get("user_plane_interface"),
                "association_status": stream.get("association_status"),
                "first_frame": stream.get("first_frame"),
                "last_frame": stream.get("last_frame"),
                "observed_g_pdu_packet_count": stream.get("observed_g_pdu_packet_count"),
                "observed_payload_byte_count": stream.get("observed_payload_byte_count"),
                "matched_subject_reference": stream.get("matched_subject_reference"),
            }
        )
    rows.sort(
        key=lambda row: (
            row["first_frame"] if isinstance(row["first_frame"], int) else 1 << 30,
            str(row["stream_reference"]),
        )
    )
    return rows


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    sources = [path for path in (args.gtpu, args.streams, args.default_bearer, args.gtpv2) if path is not None]
    try:
        events = read_jsonl(args.gtpu)
        streams = read_json(args.streams)
        default_bearer = read_json(args.default_bearer) if args.default_bearer is not None else None
        gtpv2 = read_jsonl(args.gtpv2) if args.gtpv2 is not None else []
        analysis = analyze(
            events,
            streams,
            default_bearer=default_bearer,
            gtpv2_events=gtpv2,
            provenance={
                "gtpu_events": safe_name(args.gtpu),
                "gtpu_event_count": len(events),
                "stream_summary": safe_name(args.streams),
                "stream_count": len(streams.get("streams") or []),
                "default_bearer_analysis": safe_name(args.default_bearer) if args.default_bearer else None,
                "gtpv2_events": safe_name(args.gtpv2) if args.gtpv2 else None,
                "gtpv2_event_count": len(gtpv2),
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
            print(f"wrote {len(rows)} stream timeline record(s) to {args.timeline_output.name}")
        print(
            f"wrote EPC S1-U observation for {analysis['stream_count']} stream(s) "
            f"({analysis['supported_stream_count']} supported, {analysis['ambiguous_stream_count']} ambiguous, "
            f"{analysis['unbound_stream_count']} unbound) to {args.output.name}"
        )
        return 0 if analysis["stream_count"] else EXIT_NO_STREAMS
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
