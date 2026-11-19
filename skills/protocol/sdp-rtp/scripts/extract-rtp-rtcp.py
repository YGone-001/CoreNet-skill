#!/usr/bin/env python3
"""Extract bounded RTP version 2 and RTCP subset packet evidence."""

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

from rtp_rtcp_model import (  # noqa: E402
    InputError,
    ToolError,
    build_analysis,
    extract_capture,
    extract_structured,
    validate_analysis,
)

EXIT_MALFORMED_INPUT = 2
EXIT_NO_EVENTS = 3
EXIT_EXTRACTION_FAILURE = 4
EXIT_TOOL_UNAVAILABLE = 5
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--input", type=Path, required=True, help="structured JSONL or PCAP/PCAPNG")
    result.add_argument(
        "--input-format",
        choices=("jsonl", "capture"),
        required=True,
        help="structured JSONL or authorized capture input",
    )
    result.add_argument("--output", type=Path, required=True, help="event JSON destination")
    result.add_argument("--report", type=Path, help="optional text report destination")
    result.add_argument(
        "--decode-as",
        action="append",
        default=[],
        metavar="TSHARK_DECODE_AS",
        help="explicit TShark -d mapping, for example udp.port==5004,rtp",
    )
    result.add_argument("--force", action="store_true", help="replace existing outputs")
    return result


def _same(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    if args.input_format == "jsonl" and args.decode_as:
        raise OSError("--decode-as is only valid for capture input")
    outputs = [args.output] + ([args.report] if args.report else [])
    for output in outputs:
        if _same(output, args.input):
            raise OSError("output destination collides with the input")
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
    lines = [
        "RTP/RTCP packet evidence",
        f"analysis_version: {document['analysis_version']}",
        f"mode: {document['input_provenance']['mode']}",
        f"capture: {document['input_provenance']['capture_files'][0]}",
        f"records: {document['event_count']}",
        f"RTP packets: {completeness['rtp_packet_count']}",
        f"RTCP components: {completeness['rtcp_component_count']}",
        f"SR/RR/SDES/BYE: {completeness['sr_component_count']}/"
        f"{completeness['rr_component_count']}/{completeness['sdes_component_count']}/"
        f"{completeness['bye_component_count']}",
        f"unsupported components: {completeness['unsupported_component_count']}",
        f"status: observed={completeness['observed_event_count']}, "
        f"incomplete={completeness['incomplete_event_count']}, "
        f"ambiguous={completeness['ambiguous_event_count']}, "
        f"unsupported={completeness['unsupported_event_count']}, "
        f"invalid={completeness['invalid_event_count']}",
    ]
    for event in document["events"]:
        lines.append(
            f"event: {event['event_reference']} / {event['protocol']} / "
            f"{event['evidence_status']} / frame={event['frame_number']}"
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
        if args.input_format == "jsonl":
            events, provenance = extract_structured(args.input)
        else:
            events, provenance = extract_capture(args.input, args.decode_as)
        if not events:
            print("extract-rtp-rtcp: input contains no RTP or RTCP events", file=sys.stderr)
            return EXIT_NO_EVENTS
        document = build_analysis(events, provenance)
        validate_analysis(document)
    except OSError as exc:
        print(f"extract-rtp-rtcp: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except InputError as exc:
        print(f"extract-rtp-rtcp: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except ToolError as exc:
        print(f"extract-rtp-rtcp: {exc.code}: {exc}", file=sys.stderr)
        return (
            EXIT_TOOL_UNAVAILABLE
            if exc.code.startswith("TSHARK_")
            else EXIT_EXTRACTION_FAILURE
        )
    _write_atomic(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(f"extracted {len(events)} RTP/RTCP event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())