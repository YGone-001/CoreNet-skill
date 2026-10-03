#!/usr/bin/env python3
"""Render a concise protocol-local timeline from detailed SBI HTTP/2 events.

The timeline shows observed HTTP/2 and SBI event provenance: timestamp, frame number,
connection context, stream ID, HTTP method/status, SBI operation, SM Context reference,
PDU Session ID, DNN, multipart N1/N2 part presence, ProblemDetails cause, and transport
errors.

It never prints an SMF bug or telecom session verdict (no 'SMF FAILURE',
'PDU SESSION FAILED', 'PDU SESSION SUCCESS', or 'AMF BUG').
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sbi_model import (
    EXIT_MALFORMED_INPUT,
    EXIT_NO_EVENTS,
    EXIT_OUTPUT_FAILURE,
    InputError,
    connection_context,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("events", type=Path, help="detailed SBI HTTP/2 event JSONL input")
    result.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    result.add_argument("--output", type=Path, help="output destination (defaults to stdout)")
    return result


def read_events(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")

    events: list[dict[str, object]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"unable to read events file: {path}: {exc}") from exc

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(f"invalid JSON at line {line_number} of {path}: {exc}") from exc
        if not isinstance(event, dict):
            raise InputError(f"event at line {line_number} of {path} is not a JSON object")
        if "frame_number" not in event or "timestamp" not in event:
            raise InputError(f"event at line {line_number} lacks frame and timestamp provenance")
        events.append(event)

    if not events:
        raise InputError("no detailed SBI HTTP/2 events found in input")
    return events


def _show(value: object) -> str:
    return str(value) if value not in (None, "") else "-"


def format_text_line(event: dict[str, object]) -> str:
    ts = event.get("timestamp") or "-"
    fn = event.get("frame_number") or "-"
    conn = connection_context(event)

    h2 = event.get("http2") if isinstance(event.get("http2"), dict) else {}
    sb = event.get("sbi") if isinstance(event.get("sbi"), dict) else {}
    sm = event.get("session_management") if isinstance(event.get("session_management"), dict) else {}
    prob = event.get("problem_details") if isinstance(event.get("problem_details"), dict) else {}
    trans = event.get("transport_error") if isinstance(event.get("transport_error"), dict) else {}
    parts = event.get("multipart_parts") if isinstance(event.get("multipart_parts"), list) else []

    sid = f"stream {h2.get('stream_id')}" if h2.get("stream_id") is not None else "stream -"

    method = h2.get("method")
    status = h2.get("status")
    ftype = h2.get("frame_type")

    if method:
        action = method
    elif status:
        action = f"HTTP {status}"
    elif ftype:
        action = ftype
    else:
        action = "-"

    op = sb.get("operation") or sb.get("resource") or "-"
    if sb.get("sm_context_ref"):
        ref = f"ref={sb.get('sm_context_ref')}"
    elif sb.get("n1n2_transfer_ref"):
        ref = f"ref={sb.get('n1n2_transfer_ref')}"
    else:
        ref = "ref=-"

    extra: list[str] = []
    if sm.get("pdu_session_id") is not None:
        extra.append(f"psi={sm['pdu_session_id']}")
    if sm.get("dnn"):
        extra.append(f"dnn={sm['dnn']}")

    n1_present = any(p.get("semantic_role") in ("N1_SM_INFO", "N1_MESSAGE") for p in parts if isinstance(p, dict))
    n2_present = any(p.get("semantic_role") in ("N2_SM_INFO", "N2_INFO") for p in parts if isinstance(p, dict))
    if n1_present:
        extra.append("n1=yes")
    if n2_present:
        extra.append("n2=yes")

    namf = event.get("namf_communication") if isinstance(event.get("namf_communication"), dict) else {}
    if namf.get("transfer_cause"):
        extra.append(f"cause={namf['transfer_cause']}")
    elif namf.get("failure_cause"):
        extra.append(f"cause={namf['failure_cause']}")
    elif prob.get("cause"):
        extra.append(f"cause={prob['cause']}")

    if trans.get("type"):
        extra.append(f"{trans['type']}({trans.get('error_code') or '-'})")

    extra_str = f" | {' '.join(extra)}" if extra else ""
    return f"{ts} | frame {fn} | {conn} | {sid} | {action} {op} | {ref}{extra_str}"


def timeline_entry(event: dict[str, object]) -> dict[str, object]:
    h2 = event.get("http2") if isinstance(event.get("http2"), dict) else {}
    sb = event.get("sbi") if isinstance(event.get("sbi"), dict) else {}
    sm = event.get("session_management") if isinstance(event.get("session_management"), dict) else {}
    namf = event.get("namf_communication") if isinstance(event.get("namf_communication"), dict) else {}
    prob = event.get("problem_details") if isinstance(event.get("problem_details"), dict) else {}
    trans = event.get("transport_error") if isinstance(event.get("transport_error"), dict) else {}
    parts = event.get("multipart_parts") if isinstance(event.get("multipart_parts"), list) else []

    n1_present = any(p.get("semantic_role") in ("N1_SM_INFO", "N1_MESSAGE") for p in parts if isinstance(p, dict))
    n2_present = any(p.get("semantic_role") in ("N2_SM_INFO", "N2_INFO") for p in parts if isinstance(p, dict))

    return {
        "timestamp": event.get("timestamp"),
        "frame_number": event.get("frame_number"),
        "connection_context": connection_context(event),
        "stream_id": h2.get("stream_id"),
        "method": h2.get("method"),
        "status": h2.get("status"),
        "frame_type": h2.get("frame_type"),
        "service": sb.get("service_name"),
        "operation": sb.get("operation"),
        "resource": sb.get("resource"),
        "sm_context_ref": sb.get("sm_context_ref"),
        "n1n2_transfer_ref": sb.get("n1n2_transfer_ref"),
        "pdu_session_id": sm.get("pdu_session_id"),
        "dnn": sm.get("dnn"),
        "n1_sm_part_present": n1_present,
        "n2_sm_part_present": n2_present,
        "transfer_cause": namf.get("transfer_cause"),
        "failure_cause": namf.get("failure_cause"),
        "problem_cause": prob.get("cause"),
        "transport_error": trans.get("type"),
        "transport_error_code": trans.get("error_code"),
    }


def main() -> int:
    args = parser().parse_args()
    try:
        events = read_events(args.events)
        if args.format == "json":
            entries = [timeline_entry(e) for e in events]
            output_content = json.dumps(entries, indent=2, sort_keys=True) + "\n"
        else:
            lines = [format_text_line(e) for e in events]
            output_content = "\n".join(lines) + "\n"

        if args.output:
            if not args.output.parent.is_dir():
                raise OSError(f"output directory does not exist: {args.output.parent}")
            args.output.write_text(output_content, encoding="utf-8")
        else:
            sys.stdout.write(output_content)
        return 0
    except InputError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return EXIT_MALFORMED_INPUT
    except OSError as exc:
        print(f"output failure: {exc}", file=sys.stderr)
        return EXIT_OUTPUT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
