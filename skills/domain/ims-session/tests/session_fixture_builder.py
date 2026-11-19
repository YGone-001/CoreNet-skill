#!/usr/bin/env python3
"""Deterministic synthetic SIP artifacts for IMS session Domain tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

SKILL = Path(__file__).resolve().parents[1]
ROOT = SKILL.parents[2]
SIP_SCRIPTS = ROOT / "skills" / "protocol" / "sip" / "scripts"
for path in (SKILL / "scripts", SIP_SCRIPTS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import sip_dialogs  # noqa: E402
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

CAPTURE = "synthetic-ims-session.pcapng"
CALLER = "sip:caller@example.com"
CALLEE = "sip:callee@example.com"


def rec(
    frame: int,
    *,
    method: str | None = None,
    status: int | None = None,
    occurrence: int = 1,
    call_id: str = "CALL",
    branch: str = "z9hG4bK-A",
    cseq: int = 1,
    cseq_method: str | None = None,
    from_tag: str = "FT",
    to_tag: str | None = None,
    request_uri: str = CALLEE,
    truncated: bool = False,
) -> dict[str, Any]:
    outbound = method is not None
    source, destination = (
        ("192.0.2.10", "192.0.2.20") if outbound else ("192.0.2.20", "192.0.2.10")
    )
    headers: dict[str, Any] = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "INVITE",
        "via": [{"branch": branch, "sent_by": "192.0.2.10:5060", "transport": "UDP"}],
        "from": {"uri": CALLER, "count": 1, "tag": from_tag},
        "to": {"uri": CALLEE, "count": 1, "tag": to_tag},
        "content_length": 0,
        "body_length": 0,
        "request_uri": request_uri,
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = "OK" if 200 <= status < 300 else "Response"
    record = {
        "capture_file": CAPTURE,
        "frame_number": frame,
        "frame_time_epoch": f"1700000400.{frame:09d}",
        "frame_time_relative": f"{frame}.000000000",
        "message_occurrence": occurrence,
        "transport": {
            "protocol": "UDP",
            "source_address": source,
            "source_port": 5060,
            "destination_address": destination,
            "destination_port": 5060,
            "stream_id": None,
        },
        "headers": headers,
    }
    if truncated:
        record["capture_truncated"] = True
    return record


def build_artifacts(
    records: list[dict[str, Any]], capture: str = CAPTURE
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    messages = [sip_model.normalize_record_message(record) for record in records]
    transactions = sip_transactions.correlate(messages)
    sip_transactions.attach_transaction_references(messages, transactions)
    sip_transactions.validate_transaction_document(transactions, messages)
    dialogs = sip_dialogs.build_dialog_document(
        messages,
        transactions,
        capture_provenance={
            "input_format": "fields-jsonl",
            "capture_sha256": "0" * 64,
            "decoder": "synthetic",
            "capture_completeness": "COMPLETE",
        },
    )
    sip_dialogs.validate_dialog_document(dialogs, messages, transactions)
    events = [message["event"] for message in messages]
    return events, transactions, dialogs, messages


def write_artifacts(
    directory: Path,
    events: list[dict[str, Any]],
    transactions: dict[str, Any],
    dialogs: dict[str, Any],
) -> tuple[Path, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    event_path = directory / "session-cases-events.jsonl"
    transaction_path = directory / "session-cases-transactions.json"
    dialog_path = directory / "session-cases-dialogs.json"
    event_path.write_text(
        "\n".join(json.dumps(event, separators=(",", ":"), sort_keys=True) for event in events)
        + "\n",
        encoding="utf-8",
    )
    transaction_path.write_text(
        json.dumps(transactions, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    dialog_path.write_text(
        json.dumps(dialogs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return event_path, transaction_path, dialog_path


def main_example_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    # Initial INVITE without response.
    records.append(rec(1, method="INVITE", call_id="C1", branch="z9hG4bK-C1"))
    # Initial INVITE followed by 100 Trying.
    records.extend(
        [
            rec(2, method="INVITE", call_id="C2", branch="z9hG4bK-C2"),
            rec(3, status=100, call_id="C2", branch="z9hG4bK-C2"),
        ]
    )
    # Tagged 180 Ringing creates an Early Dialog.
    records.extend(
        [
            rec(4, method="INVITE", call_id="C3", branch="z9hG4bK-C3"),
            rec(5, status=180, call_id="C3", branch="z9hG4bK-C3", to_tag="T3"),
        ]
    )
    # Tagged 183 Session Progress creates an Early Dialog.
    records.extend(
        [
            rec(6, method="INVITE", call_id="C4", branch="z9hG4bK-C4"),
            rec(7, status=183, call_id="C4", branch="z9hG4bK-C4", to_tag="T4"),
        ]
    )
    # 200 establishes a Confirmed Dialog without provisional response.
    records.extend(
        [
            rec(8, method="INVITE", call_id="C5", branch="z9hG4bK-C5"),
            rec(9, status=200, call_id="C5", branch="z9hG4bK-C5", to_tag="T5"),
        ]
    )
    # 200 plus associated 2xx ACK.
    records.extend(
        [
            rec(10, method="INVITE", call_id="C6", branch="z9hG4bK-C6"),
            rec(11, status=200, call_id="C6", branch="z9hG4bK-C6", to_tag="T6"),
            rec(
                12,
                method="ACK",
                call_id="C6",
                branch="z9hG4bK-C6",
                to_tag="T6",
                cseq=1,
                cseq_method="ACK",
            ),
        ]
    )
    # Non-2xx final response with its ACK.
    records.extend(
        [
            rec(13, method="INVITE", call_id="C7", branch="z9hG4bK-C7"),
            rec(14, status=486, call_id="C7", branch="z9hG4bK-C7", to_tag="T7"),
            rec(
                15,
                method="ACK",
                call_id="C7",
                branch="z9hG4bK-C7",
                to_tag="T7",
                cseq=1,
                cseq_method="ACK",
            ),
        ]
    )
    # One INVITE with two independent forked 2xx branches.
    records.extend(
        [
            rec(16, method="INVITE", call_id="C8", branch="z9hG4bK-C8"),
            rec(17, status=200, call_id="C8", branch="z9hG4bK-C8", to_tag="TA"),
            rec(18, status=200, call_id="C8", branch="z9hG4bK-C8", to_tag="TB"),
            rec(
                19,
                method="ACK",
                call_id="C8",
                branch="z9hG4bK-C8",
                to_tag="TA",
                cseq=1,
                cseq_method="ACK",
            ),
            rec(
                20,
                method="ACK",
                call_id="C8",
                branch="z9hG4bK-C8",
                to_tag="TB",
                cseq=1,
                cseq_method="ACK",
            ),
        ]
    )
    # CANCEL sequence: CANCEL 200 and INVITE 487 remain separate observations.
    records.extend(
        [
            rec(21, method="INVITE", call_id="C9", branch="z9hG4bK-C9"),
            rec(22, method="CANCEL", call_id="C9", branch="z9hG4bK-C9"),
            rec(
                23,
                status=200,
                call_id="C9",
                branch="z9hG4bK-C9",
                to_tag="TC",
                cseq_method="CANCEL",
            ),
            rec(
                24,
                status=487,
                call_id="C9",
                branch="z9hG4bK-C9",
                to_tag="T487",
            ),
        ]
    )
    # BYE with 200 response on a Confirmed Dialog.
    records.extend(
        [
            rec(25, method="INVITE", call_id="C10", branch="z9hG4bK-C10"),
            rec(26, status=200, call_id="C10", branch="z9hG4bK-C10", to_tag="T10"),
            rec(
                27,
                method="ACK",
                call_id="C10",
                branch="z9hG4bK-C10",
                to_tag="T10",
                cseq=1,
                cseq_method="ACK",
            ),
            rec(28, method="BYE", call_id="C10", branch="z9hG4bK-C10", to_tag="T10", cseq=2),
            rec(
                29,
                status=200,
                call_id="C10",
                branch="z9hG4bK-C10",
                to_tag="T10",
                cseq=2,
                cseq_method="BYE",
            ),
        ]
    )
    # re-INVITE is retained only as an in-dialog observation.
    records.extend(
        [
            rec(30, method="INVITE", call_id="C11", branch="z9hG4bK-C11"),
            rec(31, status=200, call_id="C11", branch="z9hG4bK-C11", to_tag="T11"),
            rec(
                32,
                method="ACK",
                call_id="C11",
                branch="z9hG4bK-C11",
                to_tag="T11",
                cseq=1,
                cseq_method="ACK",
            ),
            rec(
                33,
                method="INVITE",
                call_id="C11",
                branch="z9hG4bK-C11B",
                to_tag="T11",
                cseq=2,
            ),
            rec(
                34,
                status=200,
                call_id="C11",
                branch="z9hG4bK-C11B",
                to_tag="T11",
                cseq=2,
            ),
        ]
    )
    return records