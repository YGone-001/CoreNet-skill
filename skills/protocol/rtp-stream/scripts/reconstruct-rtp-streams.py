#!/usr/bin/env python3
"""Reconstruct bounded RTP source streams from accepted RTP/RTCP evidence.

The CLI consumes only an already-generated ``rtp-rtcp`` Analysis JSON artifact
produced by the ``sdp-rtp`` Protocol Skill. It never reads a capture, executes
TShark, decodes an RTP packet, parses SDP, associates RTCP with RTP, or
produces a packet-loss, QoS, media-delivery or call verdict.
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

from rtp_stream_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_rtp_rtcp_analysis,
    validate_analysis,
)

EXIT_MALFORMED_INPUT = 2
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--rtp-rtcp-analysis", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--report", type=Path)
    result.add_argument("--expected-source-sha256", type=str)
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
    for output in outputs:
        if _same(output, args.rtp_rtcp_analysis):
            raise OSError("output destination collides with the input artifact")
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
    provenance = document["input_provenance"]
    completeness = document["completeness"]
    parameters = document["sequence_validation_parameters"]
    lines = [
        "RTP source-stream and sequence-integrity reconstruction",
        f"analysis_version: {document['analysis_version']}",
        f"source_artifact: {provenance['source_analysis_source_name']}",
        f"source_sha256: {provenance['source_analysis_sha256']}",
        f"capture: {provenance['capture_files'][0]}",
        f"capture_sha256: {provenance['capture_sha256']}",
        f"endpoint_context: {provenance.get('endpoint_context_reference') or '-'}",
        "sequence_parameters: "
        f"RTP_SEQ_MOD={parameters['RTP_SEQ_MOD']} "
        f"MIN_SEQUENTIAL={parameters['MIN_SEQUENTIAL']} "
        f"MAX_DROPOUT={parameters['MAX_DROPOUT']} "
        f"MAX_MISORDER={parameters['MAX_MISORDER']}",
        f"input_rtp_events: {completeness['total_input_rtp_packet_count']}",
        "streams: {} (validated={}, probation={}, ambiguous={}, insufficient={})".format(
            document["source_stream_count"],
            completeness["sequence_validated_stream_count"],
            completeness["probation_stream_count"],
            completeness["ambiguous_stream_count"],
            completeness["incomplete_stream_count"],
        ),
        "unassigned_rtp_events: {} (published={}, omitted={})".format(
            document["unassigned_packet_count"],
            completeness["published_unassigned_packet_count"],
            document["unassigned_packets_omitted"],
        ),
        f"rtcp_events: {document['rtcp_event_count']} "
        f"(status={document['rtcp_observation_status']})",
        f"duplicate_observations: {completeness['duplicate_observation_count']}",
        f"out_of_order_observations: {completeness['out_of_order_observation_count']}",
        "sequence_gaps: {} (unobserved_slots={})".format(
            completeness["sequence_gap_count"],
            sum(
                stream["unobserved_sequence_number_slot_count"]
                for stream in document["source_streams"]
            ),
        ),
        f"restart_patterns: {completeness['restart_pattern_count']}",
        f"omitted_records: {completeness['omitted_record_count']}",
    ]
    for stream in document["source_streams"]:
        lines.append(
            "stream: {} / {} / packets={} eligible={} incomplete={} excluded={}".format(
                stream["source_stream_reference"],
                stream["sequence_validation_status"],
                stream["rtp_packet_count"],
                stream["sequence_eligible_packet_count"],
                stream["incomplete_packet_count"],
                stream["invalid_or_excluded_packet_count"],
            )
        )
        lines.append(
            "  payload_types: {}".format(
                ", ".join(str(item) for item in stream["observed_payload_types"]) or "-"
            )
        )
        lines.append(
            "  frames: {}..{}".format(
                stream["first_frame_number"], stream["last_frame_number"]
            )
        )
        lines.append(
            "  endpoints: source={}({}) destination={}({}) evidence={}".format(
                stream["source_endpoint_identity_status"],
                len(stream["source_endpoint_references"]),
                stream["destination_endpoint_identity_status"],
                len(stream["destination_endpoint_references"]),
                stream["endpoint_evidence_status"],
            )
        )
        lines.append(
            "  sequence: epochs={} wraps={} duplicates={} out_of_order={} "
            "gaps={} unobserved={} restarts={}".format(
                stream["sequence_epoch_count"],
                stream["sequence_wrap_count"],
                stream["duplicate_sequence_observation_count"],
                stream["out_of_order_packet_count"],
                stream["observed_sequence_gap_count"],
                stream["unobserved_sequence_number_slot_count"],
                stream["restart_pattern_count"],
            )
        )
        for epoch in stream["sequence_epochs"]:
            lines.append(
                "  epoch: {} / {} / first={} last={} extended={}..{} "
                "unique={} wraps={} gaps={} duplicates={} out_of_order={}".format(
                    epoch["epoch_index"],
                    epoch["sequence_validation_status"],
                    epoch["first_observed_sequence_number"],
                    epoch["last_observed_sequence_number"],
                    epoch["extended_sequence_start"],
                    epoch["extended_sequence_end"],
                    epoch["unique_sequence_count"],
                    epoch["sequence_wrap_count"],
                    epoch["observed_gap_count"],
                    epoch["duplicate_observation_count"],
                    epoch["out_of_order_observation_count"],
                )
            )
        for gap in stream["sequence_gaps"]:
            lines.append(
                "  gap: {} / epoch={} / {}..{} / unobserved={} / filled={}".format(
                    gap["gap_reference"],
                    gap["epoch_index"],
                    gap["start_extended_sequence_position"],
                    gap["end_extended_sequence_position"],
                    gap["unobserved_sequence_number_count"],
                    "yes" if gap["filled_by_later_observation"] else "no",
                )
            )
        for pattern in stream["restart_patterns"]:
            lines.append(
                "  restart: {} / {} / epoch {} -> {}".format(
                    pattern["restart_reference"],
                    pattern["restart_confirmation"],
                    pattern["previous_epoch_index"],
                    pattern["new_epoch_index"],
                )
            )
        for item in stream["missing_evidence"]:
            lines.append(f"  missing: {item}")
        for item in stream["conflict_findings"]:
            lines.append(f"  conflict: {item}")
    for packet in document["unassigned_packets"]:
        lines.append(
            "unassigned: {} / {} / reasons={}".format(
                packet["event_reference"],
                packet["original_evidence_status"],
                ", ".join(packet["reason_codes"]),
            )
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
        source, provenance, actual_sha = load_rtp_rtcp_analysis(
            args.rtp_rtcp_analysis,
            expected_source_sha256=args.expected_source_sha256,
        )
        document = build_analysis(source, provenance=provenance)
        validate_analysis(document)
    except OSError as exc:
        print(f"reconstruct-rtp-streams: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except InputError as exc:
        print(f"reconstruct-rtp-streams: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    _write_atomic(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(
        "reconstructed {} RTP source stream(s) from {} accepted RTP event(s) "
        "of source artifact {}".format(
            document["source_stream_count"],
            document["completeness"]["total_input_rtp_packet_count"],
            actual_sha,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())