#!/usr/bin/env python3
"""Deterministic synthetic SIP, IMS Session and SDP artifacts for Domain tests."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SKILL = Path(__file__).resolve().parents[1]
SKILLS = SKILL.parents[1]
for path in (
    SKILL / "scripts",
    SKILLS / "protocol" / "sip" / "scripts",
    SKILLS / "protocol" / "sdp-rtp" / "scripts",
    SKILLS / "domain" / "ims-session" / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_session_model  # noqa: E402
import sdp_model  # noqa: E402
import sip_dialogs  # noqa: E402
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

CAPTURE = "synthetic-ims-media.pcapng"
CAPTURE_SHA = "b7" * 32
CALLER = "sip:caller@example.com"
CALLEE = "sip:callee@example.com"

AUDIO_OFFER = (
    "v=0\r\n"
    "o=- 1000 1 IN IP4 192.0.2.10\r\n"
    "s=offer\r\n"
    "c=IN IP4 192.0.2.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=sendrecv\r\n"
)
AUDIO_ANSWER = (
    "v=0\r\n"
    "o=- 2000 1 IN IP4 192.0.2.20\r\n"
    "s=answer\r\n"
    "c=IN IP4 192.0.2.20\r\n"
    "t=0 0\r\n"
    "m=audio 49200 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)


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
    sdp_body: str | None = None,
    content_type: str | None = None,
    body_length: int | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    outbound = method is not None
    source, destination = (
        ("192.0.2.10", "192.0.2.20") if outbound else ("192.0.2.20", "192.0.2.10")
    )
    body_bytes = len((sdp_body or "").encode("utf-8"))
    effective_body = body_length if body_length is not None else body_bytes
    headers: dict[str, Any] = {
        "call_id": call_id,
        "cseq_sequence": cseq,
        "cseq_method": cseq_method or method or "INVITE",
        "via": [{"branch": branch, "sent_by": "192.0.2.10:5060", "transport": "UDP"}],
        "from": {"uri": CALLER, "count": 1, "tag": from_tag},
        "to": {"uri": CALLEE, "count": 1, "tag": to_tag},
        "content_type": content_type or ("application/sdp" if sdp_body else None),
        "content_length": effective_body,
        "body_length": effective_body,
        "request_uri": request_uri,
    }
    if method is not None:
        headers["method"] = method
        headers["max_forwards"] = 70
    if status is not None:
        headers["status_code"] = status
        headers["reason_phrase"] = "OK" if 200 <= status < 300 else "Response"
    record: dict[str, Any] = {
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
        "sdp_body": sdp_body,
    }
    if truncated:
        record["capture_truncated"] = True
    return record


def sdp_record(
    reference: str,
    frame: int,
    occurrence: int,
    body: str,
    *,
    capture: str = CAPTURE,
    capture_sha256: str = CAPTURE_SHA,
) -> dict[str, Any]:
    return {
        "source_reference": reference,
        "capture_file": capture,
        "capture_sha256": capture_sha256,
        "frame_number": frame,
        "frame_reference": f"frame-{frame}",
        "message_occurrence": occurrence,
        "sdp_body": body,
    }


def build_records() -> list[dict[str, Any]]:
    return [
        rec(1, method="INVITE", sdp_body=AUDIO_OFFER),
        rec(2, status=100, cseq_method="INVITE"),
        rec(3, status=180, cseq_method="INVITE", to_tag="TT-1"),
        rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=AUDIO_ANSWER),
        rec(5, method="ACK", cseq=1, to_tag="TT-1"),
    ]


def late_offer_records() -> list[dict[str, Any]]:
    return [
        rec(1, method="INVITE"),
        rec(2, status=100, cseq_method="INVITE"),
        rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=AUDIO_OFFER),
        rec(4, method="ACK", cseq=1, to_tag="TT-1", sdp_body=AUDIO_ANSWER),
    ]


def fork_records() -> list[dict[str, Any]]:
    return [
        rec(1, method="INVITE", sdp_body=AUDIO_OFFER),
        rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
        rec(3, status=180, cseq_method="INVITE", to_tag="TT-2"),
        rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=AUDIO_ANSWER),
        rec(5, status=200, cseq_method="INVITE", to_tag="TT-2", sdp_body=AUDIO_ANSWER),
        rec(6, method="ACK", cseq=1, to_tag="TT-1"),
        rec(7, method="ACK", cseq=1, to_tag="TT-2"),
    ]


def terminated_records() -> list[dict[str, Any]]:
    return build_records() + [
        rec(6, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        rec(7, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
    ]


def terminated_late_offer_records() -> list[dict[str, Any]]:
    return late_offer_records() + [
        rec(5, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        rec(6, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
    ]


def forked_terminated_records() -> list[dict[str, Any]]:
    return fork_records() + [
        rec(8, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        rec(9, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
    ]


def unacknowledged_bye_records() -> list[dict[str, Any]]:
    return build_records() + [
        rec(6, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1")
    ]


def negative_bye_records() -> list[dict[str, Any]]:
    return build_records() + [
        rec(6, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        rec(7, status=481, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
    ]


def build_artifacts(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    messages = [
        sip_model.normalize_record_message(
            {key: value for key, value in record.items() if key != "sdp_body"}
        )
        for record in records
    ]
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
    return [message["event"] for message in messages], transactions, dialogs


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_inputs(
    directory: Path,
    records: list[dict[str, Any]],
    *,
    sdp_records: list[dict[str, Any]] | None = None,
    events: list[dict[str, Any]] | None = None,
    session_mutation=None,
    sdp_mutation=None,
    prefix: str = "media-",
) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    built_events, transactions, dialogs = build_artifacts(records)
    if events is not None:
        built_events = events
    events = built_events
    event_references = [event["source_reference"] for event in events]
    event_path = directory / f"{prefix}events.jsonl"
    event_path.write_text(
        "\n".join(json.dumps(event, separators=(",", ":"), sort_keys=True) for event in events)
        + "\n",
        encoding="utf-8",
    )
    transaction_path = directory / f"{prefix}transactions.json"
    dialog_path = directory / f"{prefix}dialogs.json"
    _write_json(transaction_path, transactions)
    _write_json(dialog_path, dialogs)
    session = ims_session_model.build_analysis(
        events,
        transactions,
        dialogs,
        provenance={
            "event_source_name": event_path.name,
            "event_sha256": _sha256(event_path),
            "transaction_source_name": transaction_path.name,
            "transaction_sha256": _sha256(transaction_path),
            "dialog_source_name": dialog_path.name,
            "dialog_sha256": _sha256(dialog_path),
        },
    )
    if session_mutation is not None:
        session_mutation(session)
    session_path = directory / f"{prefix}ims-session.json"
    _write_json(session_path, session)
    if sdp_records is None:
        sdp_records = [
            sdp_record(reference, event["frame_number"], event["message_occurrence"], record["sdp_body"])
            for record, event, reference in zip(records, events, event_references)
            if record.get("sdp_body")
        ]
    if not sdp_records:
        sdp_records = [
            sdp_record(f"sdp-unmatched:{CAPTURE}:999.1", 999, 1, AUDIO_OFFER)
        ]
    sdp = sdp_model.build_analysis(sdp_records, input_name="media-sdp-input.jsonl")
    if sdp_mutation is not None:
        sdp_mutation(sdp)
    sdp_path = directory / f"{prefix}sdp-analysis.json"
    _write_json(sdp_path, sdp)
    return {
        "events": event_path,
        "session": session_path,
        "sdp": sdp_path,
        "transactions": transaction_path,
        "dialogs": dialog_path,
        "session_document": session,
        "sdp_document": sdp,
        "event_references": event_references,
    }