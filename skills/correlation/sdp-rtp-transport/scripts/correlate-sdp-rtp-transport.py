#!/usr/bin/env python3
"""Correlate accepted SDP media endpoints with accepted RTP UDP streams.

The CLI consumes only already-generated SDP and RTP/RTCP analysis JSON. It
does not need the HMAC key: endpoint references are already opaque and
capture-scoped. It never reads a capture, parses SDP, decodes RTP or infers an
IMS session identity, media-delivery outcome or call result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from sdp_rtp_transport_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_rtp_analysis,
    load_sdp_analysis,
    validate_analysis,
    verify_provenance,
)

EXIT_MALFORMED_INPUT = 2
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--sdp-analysis", type=Path, required=True)
    result.add_argument("--rtp-rtcp-analysis", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--report", type=Path)
    result.add_argument("--force", action="store_true")
    return result


def _same(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    outputs = [args.output] + ([args.report] if args.report else [])
    inputs = [args.sdp_analysis, args.rtp_rtcp_analysis]
    for output in outputs:
        if any(_same(output, item) for item in inputs):
            raise OSError("output destination collides with an input")
        if output.exists() and not args.force:
            raise OSError("output already exists; use --force to replace it")
        if not output.parent.is_dir():
            raise OSError("output directory does not exist")
    if args.report is not None and _same(args.output, args.report):
        raise OSError("JSON and report destinations must differ")


def _write_atomic(path: Path, payload: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as handle:
            temporary = handle.name
            handle.write(payload)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)


def _report(document: dict) -> str:
    completeness = document["completeness"]
    provenance = document["input_provenance"]
    lines = [
        "SDP / RTP UDP transport endpoint correlation",
        f"analysis_version: {document['analysis_version']}",
        f"capture: {provenance['capture_files'][0]}",
        f"endpoint_context: {provenance.get('endpoint_context_reference') or '-'}",
        f"correlations: {document['correlation_count']}",
        "status: matched={}, bundle={}, ambiguous={}, insufficient={}, unmatched={}, out_of_scope={}".format(
            completeness["matched_correlation_count"],
            completeness["bundle_matched_correlation_count"],
            completeness["ambiguous_correlation_count"],
            completeness["insufficient_correlation_count"],
            completeness["unmatched_correlation_count"],
            completeness["out_of_scope_correlation_count"],
        ),
        f"rtp_streams: {completeness['rtp_stream_count']} "
        f"(with_endpoint={completeness['rtp_stream_with_endpoint_count']})",
        f"unmatched_streams: {document['unmatched_stream_count']}",
    ]
    for correlation in document["correlations"]:
        media = ", ".join(
            f"{item['message_reference']}#{item['media_index']}"
            for item in correlation["sdp_media_sections"]
        )
        streams = ", ".join(correlation["rtp_udp_stream_references"]) or "-"
        directions = ", ".join(correlation["match_directions"]) or "-"
        lines.append(
            f"correlation: {correlation['correlation_reference']} / "
            f"{correlation['association_status']} / "
            f"{correlation['correlation_strength']} / media={media} / "
            f"streams={streams} / directions={directions}"
        )
        for item in correlation["missing_evidence"]:
            lines.append(f"  missing: {item}")
        for item in correlation["conflict_findings"]:
            lines.append(f"  conflict: {item}")
    for stream in document["unmatched_streams"]:
        lines.append(
            f"unmatched_stream: {stream['rtp_udp_stream_reference']} / "
            f"{stream['endpoint_evidence_status']} / packets={stream['packet_count']}"
        )
    lines.append("limits:")
    lines.extend(f"- {item}" for item in document["limitations"])
    lines.append("not_confirmed:")
    lines.extend(f"- {item}" for item in document["not_confirmed"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _preflight(args)
        sdp = load_sdp_analysis(args.sdp_analysis)
        rtp = load_rtp_analysis(args.rtp_rtcp_analysis)
        provenance = verify_provenance(
            sdp,
            rtp,
            sdp_path=args.sdp_analysis,
            rtp_path=args.rtp_rtcp_analysis,
        )
        document = build_analysis(sdp, rtp, provenance=provenance)
        validate_analysis(document)
    except OSError as exc:
        print(f"correlate-sdp-rtp-transport: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except InputError as exc:
        print(f"correlate-sdp-rtp-transport: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    _write_atomic(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(
        f"correlated {document['correlation_count']} SDP media section(s) "
        f"against {document['completeness']['rtp_stream_count']} RTP stream(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())