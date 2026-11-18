#!/usr/bin/env python3
"""Analyze bounded IMS registration evidence from SIP and optional Diameter IMS.

SIP messages and transactions are produced by the accepted SIP Protocol Skill.
The optional Diameter IMS artifact is consumed as an independent observation
inventory; no SIP-to-Diameter subscriber identity association is invented.

The analyzer decodes no packets, publishes no raw subscriber identity or
authentication value, and does not issue session, media or call verdicts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SIP_SCRIPTS = HERE.parents[2] / "protocol" / "sip" / "scripts"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SIP_SCRIPTS))

import sip_model  # noqa: E402
import sip_transactions  # noqa: E402
from ims_registration_model import (  # noqa: E402
    ANALYSIS_NAME,
    ANALYSIS_VERSION,
    InputError,
    build_analysis,
    sanitize,
    validate_analysis,
    _load_diameter,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--sip-input", type=Path, required=True, help="SIP capture, PDML or sanitized JSONL")
    result.add_argument(
        "--input-format",
        choices=("auto", "capture", "pdml", "fields-jsonl"),
        default="auto",
        help="SIP input interpretation; auto uses the file extension",
    )
    result.add_argument("--diameter-ims", type=Path, help="optional Diameter IMS analysis JSON")
    result.add_argument("--output", type=Path, required=True, help="registration analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional text report destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _resolved_format(source: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = source.suffix.lower()
    if suffix == ".pdml":
        return "pdml"
    if suffix in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    return "capture"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_artifact(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    inputs = [args.sip_input]
    if args.diameter_ims is not None:
        inputs.append(args.diameter_ims)
    outputs = [args.output]
    if args.report is not None:
        outputs.append(args.report)
    for output in outputs:
        for source in inputs:
            if _same_artifact(output, source):
                raise OSError("output destination collides with an input artifact")
    if len(outputs) == 2 and _same_artifact(outputs[0], outputs[1]):
        raise OSError("JSON output and text report destinations must be distinct")
    for output in outputs:
        if output.exists() and not args.force:
            raise OSError("output already exists; use --force to replace it")
        if not output.parent.is_dir():
            raise OSError("output directory does not exist")


def _write_atomic(path: Path, payload: str) -> None:
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", delete=False, dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
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
    attempts = document["registration_attempts"]
    lines = [
        "IMS registration evidence",
        f"analysis_version: {document['analysis_version']}",
        f"sip_events: {completeness['sip_event_count']}",
        f"sip_transactions: {completeness['sip_transaction_count']}",
        f"register_transactions: {completeness['register_transaction_count']}",
        f"registration_attempts: {completeness['attempt_count']}",
        f"diameter_observations: {completeness['diameter_observation_count']}",
        f"cross_protocol_associations: {completeness['association_count']}",
        f"timeline_rows: {completeness['timeline_row_count']}",
    ]
    for attempt in attempts:
        lines.append(
            "attempt: "
            f"{attempt['registration_type']} / "
            f"{attempt['authentication_evidence_status']} / "
            f"{attempt['sip_outcome']}"
        )
    lines.append("not_confirmed:")
    lines.extend(f"- {item}" for item in document["not_confirmed"])
    lines.append("limitations:")
    lines.extend(f"- {item}" for item in document["limitations"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        _preflight(args)
        input_format = _resolved_format(args.sip_input, args.input_format)
        messages, decoder = sip_model.messages_for_input(args.sip_input, args.input_format)
        if not messages:
            print("input contains no SIP messages", file=sys.stderr)
            return sip_model.EXIT_NO_EVENTS
        transaction_document = sip_transactions.correlate(messages)
        sip_transactions.attach_transaction_references(messages, transaction_document)
        sip_transactions.validate_transaction_document(transaction_document, messages)

        diameter_document = None
        diameter_evidence = None
        if args.diameter_ims is not None:
            diameter_document, diameter_evidence = _load_diameter(args.diameter_ims)

        provenance = {
            "source_name": args.sip_input.name,
            "source_sha256": _sha256(args.sip_input),
            "input_format": input_format,
            "decoder": decoder,
        }
        document = build_analysis(
            messages,
            transaction_document,
            diameter_document=diameter_document,
            diameter_evidence=diameter_evidence,
            sip_provenance=provenance,
        )
        event_references = {message["match"]["source_reference"] for message in messages}
        transaction_references = {
            transaction["transaction_reference"] for transaction in transaction_document["transactions"]
        }
        validate_analysis(
            document,
            sip_event_references=event_references,
            transaction_references=transaction_references,
        )
        sanitize(document)
        _write_atomic(args.output, json.dumps(document, sort_keys=True, indent=2) + "\n")
        if args.report is not None:
            _write_atomic(args.report, _report(document))
        print(
            f"analyzed {document['completeness']['register_transaction_count']} REGISTER transaction(s), "
            f"{document['completeness']['attempt_count']} registration attempt(s), "
            f"{document['completeness']['diameter_observation_count']} Diameter observation(s)"
        )
        if args.report is not None:
            print(f"wrote report to {args.report.name}")
    except sip_model.ToolUnavailable as exc:
        print(f"tool unavailable: {exc}", file=sys.stderr)
        return sip_model.EXIT_TOOL_UNAVAILABLE
    except sip_model.TsharkError as exc:
        print(f"tshark failure: {exc}", file=sys.stderr)
        return sip_model.EXIT_TSHARK_FAILURE
    except (sip_model.InputError, InputError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return sip_model.EXIT_MALFORMED_INPUT
    except sip_transactions.TransactionError as exc:
        print(f"transaction error: {exc}", file=sys.stderr)
        return sip_model.EXIT_OUTPUT_FAILURE
    except (json.JSONDecodeError, OSError) as exc:
        print(f"output error: {exc}", file=sys.stderr)
        return sip_model.EXIT_OUTPUT_FAILURE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())