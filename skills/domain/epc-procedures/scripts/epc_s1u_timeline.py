#!/usr/bin/env python3
"""Render a bounded EPC S1-U observation as a stream timeline.

Reads the analysis JSON produced by `analyze_epc_s1u.py`; it never re-runs the
analysis and never reads a capture.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from epc_s1u_model import EXIT_MALFORMED_INPUT, InputError, read_json


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("analysis", type=Path, help="S1-U observation JSON")
    result.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    return result


def rows(analysis: dict) -> list[dict]:
    collected: list[dict] = []
    for stream in analysis.get("stream_observations") or []:
        if not isinstance(stream, dict):
            continue
        collected.append(
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
    collected.sort(
        key=lambda row: (
            row["first_frame"] if isinstance(row["first_frame"], int) else 1 << 30,
            str(row["stream_reference"]),
        )
    )
    return collected


def render_text(analysis: dict) -> str:
    lines = [
        "EPC S1-U GTP-U observation",
        f"  streams: {analysis.get('stream_count', 0)}",
        f"  supported: {analysis.get('supported_stream_count', 0)}",
        f"  ambiguous: {analysis.get('ambiguous_stream_count', 0)}",
        f"  unbound: {analysis.get('unbound_stream_count', 0)}",
        f"  observed G-PDU packets: {analysis.get('observed_g_pdu_packet_count', 0)}",
        f"  observed payload octets: {analysis.get('observed_payload_byte_count', 0)}",
        "",
    ]
    for row in rows(analysis):
        lines.append(
            f"{row['stream_reference']} {row['direction']} {row['association_status']} "
            f"{row['outer_source']} -> {row['outer_destination']} teid={row['teid']} "
            f"g-pdu={row['observed_g_pdu_packet_count']} octets={row['observed_payload_byte_count']} "
            f"frames {row['first_frame']}-{row['last_frame']}"
        )
        if row["matched_subject_reference"]:
            lines.append(f"  bearer subject: {row['matched_subject_reference']}")
    for limitation in analysis.get("evidence_limitations") or []:
        lines.append(f"limitation: {limitation}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        analysis = read_json(args.analysis)
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    if args.format == "json":
        for row in rows(analysis):
            print(json.dumps(row, sort_keys=True))
    else:
        sys.stdout.write(render_text(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
