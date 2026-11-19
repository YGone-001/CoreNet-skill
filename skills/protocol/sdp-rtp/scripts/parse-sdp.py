#!/usr/bin/env python3
"""Parse explicitly supplied SDP bodies into bounded structural evidence."""

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

from sdp_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_messages,
    validate_analysis,
)

EXIT_MALFORMED_INPUT = 2
EXIT_NO_EVENTS = 3
EXIT_OUTPUT_FAILURE = 6


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--input",
        type=Path,
        required=True,
        help="JSONL file containing SDP bodies and caller-supplied provenance",
    )
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional text report destination")
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
        "SDP structural evidence",
        f"analysis_version: {document['analysis_version']}",
        f"capture: {document['input_provenance']['capture_files'][0]}",
        f"messages: {completeness['published_message_count']} published",
        f"status: observed={completeness['observed_message_count']}, "
        f"incomplete={completeness['incomplete_message_count']}, "
        f"ambiguous={completeness['ambiguous_message_count']}, "
        f"unsupported={completeness['unsupported_message_count']}, "
        f"invalid={completeness['invalid_message_count']}",
    ]
    for message in document["messages"]:
        lines.append(
            f"message: {message['source_reference']} / {message['evidence_status']} / "
            f"media_sections={message['media_section_count']} / "
            f"line_endings={message['line_ending_style']}"
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
        records = load_messages(args.input)
        document = build_analysis(records, input_name=args.input.name)
        validate_analysis(document)
    except OSError as exc:
        print(f"parse-sdp: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE
    except InputError as exc:
        message = str(exc)
        print(f"parse-sdp: {message}", file=sys.stderr)
        return EXIT_NO_EVENTS if "contains no SDP messages" in message else EXIT_MALFORMED_INPUT
    _write_atomic(args.output, json.dumps(document, indent=2, sort_keys=True) + "\n")
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(f"parsed {len(records)} SDP message(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())