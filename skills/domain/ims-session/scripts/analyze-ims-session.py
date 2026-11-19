#!/usr/bin/env python3
"""Analyze bounded IMS session establishment and release signaling evidence.

Consumes accepted SIP Event JSONL, SIP Transaction JSON and SIP Dialog JSON.
Performs no packet decoding, transaction rematching or dialog reconstruction.
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

from ims_session_model import (  # noqa: E402
    InputError,
    build_analysis,
    load_inputs,
    validate_analysis,
)

EXIT_INPUT = 2


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--sip-events", type=Path, required=True, help="SIP Event JSONL input")
    result.add_argument(
        "--sip-transactions", type=Path, required=True, help="SIP Transaction JSON input"
    )
    result.add_argument("--sip-dialogs", type=Path, required=True, help="SIP Dialog JSON input")
    result.add_argument("--output", type=Path, required=True, help="analysis JSON destination")
    result.add_argument("--report", type=Path, help="optional text report destination")
    result.add_argument("--force", action="store_true", help="explicitly replace existing outputs")
    return result


def _same_artifact(left: Path, right: Path) -> bool:
    try:
        if left.resolve() == right.resolve():
            return True
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _preflight(args: argparse.Namespace) -> None:
    inputs = [args.sip_events, args.sip_transactions, args.sip_dialogs]
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
        "IMS session evidence",
        f"analysis_version: {document['analysis_version']}",
        f"capture: {document['input_provenance']['capture_files'][0]}",
        f"sip_events: {completeness['sip_event_count']}",
        f"sip_transactions: {completeness['sip_transaction_count']}",
        f"sip_dialogs: {completeness['sip_dialog_count']}",
        f"session_attempts: {completeness['session_attempt_count']}",
        f"branches: {completeness['branch_count']}",
        f"unbound_observations: {completeness['unbound_observation_count']}",
        f"in_dialog_observations: {completeness['in_dialog_observation_count']}",
        f"capture_completeness: {completeness['capture_completeness']}",
    ]
    for attempt in document["session_attempts"]:
        lines.append(
            "attempt: "
            f"{attempt['attempt_reference']} / "
            f"{attempt['invite_outcome']} / "
            f"branches={attempt['branch_count']} / "
            f"ack={attempt['ack_evidence']['status']} / "
            f"cancel={attempt['cancel_evidence']['outcome']} / "
            f"release={attempt['release_evidence']['outcome']}"
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
        events, transactions, dialogs, provenance = load_inputs(
            args.sip_events, args.sip_transactions, args.sip_dialogs
        )
        document = build_analysis(
            events, transactions, dialogs, provenance=provenance
        )
        validate_analysis(
            document,
            event_references={event["source_reference"] for event in events},
            transaction_references={
                item["transaction_reference"] for item in transactions["transactions"]
            },
            dialog_references={
                item["dialog_reference"] for item in dialogs["dialogs"]
            },
        )
    except (InputError, OSError) as exc:
        print(f"analyze-ims-session: {exc}", file=sys.stderr)
        return EXIT_INPUT

    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_atomic(args.output, payload)
    if args.report is not None:
        _write_atomic(args.report, _report(document))
        print(f"wrote report to {args.report}")
    print(
        f"analyzed {len(events)} SIP event(s), "
        f"{len(transactions['transactions'])} transaction(s), "
        f"{len(dialogs['dialogs'])} dialog(s), "
        f"{len(document['session_attempts'])} session attempt(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())