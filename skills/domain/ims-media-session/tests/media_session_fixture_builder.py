#!/usr/bin/env python3
"""Deterministic synthetic four-artifact fixtures for the IMS media session Domain."""

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
    SKILLS / "protocol" / "sdp-rtp" / "scripts",
    SKILLS / "domain" / "ims-session" / "scripts",
    SKILLS / "domain" / "ims-media-signaling" / "scripts",
    SKILLS / "domain" / "ims-media-signaling" / "tests",
    SKILLS / "correlation" / "sdp-rtp-transport" / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import ims_media_signaling_model  # noqa: E402
import ims_session_model  # noqa: E402
import media_fixture_builder as upstream  # noqa: E402
import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402
import sdp_rtp_transport_model  # noqa: E402

CAPTURE = upstream.CAPTURE
CAPTURE_SHA = upstream.CAPTURE_SHA
KEY = hashlib.sha256(b"synthetic-ims-media-session-test-key").digest()

OFFER = upstream.AUDIO_OFFER
ANSWER_ONE = (
    "v=0\r\n"
    "o=- 2001 1 IN IP4 192.0.2.21\r\n"
    "s=answer-one\r\n"
    "c=IN IP4 192.0.2.21\r\n"
    "t=0 0\r\n"
    "m=audio 49200 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)
ANSWER_TWO = (
    "v=0\r\n"
    "o=- 2002 1 IN IP4 192.0.2.22\r\n"
    "s=answer-two\r\n"
    "c=IN IP4 192.0.2.22\r\n"
    "t=0 0\r\n"
    "m=audio 49200 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=sendrecv\r\n"
)


def fork_terminated_records() -> list[dict[str, Any]]:
    return [
        upstream.rec(1, method="INVITE", sdp_body=OFFER),
        upstream.rec(2, status=180, cseq_method="INVITE", to_tag="TT-1"),
        upstream.rec(3, status=180, cseq_method="INVITE", to_tag="TT-2"),
        upstream.rec(4, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=ANSWER_ONE),
        upstream.rec(5, status=200, cseq_method="INVITE", to_tag="TT-2", sdp_body=ANSWER_TWO),
        upstream.rec(6, method="ACK", cseq=1, to_tag="TT-1"),
        upstream.rec(7, method="ACK", cseq=1, to_tag="TT-2"),
        upstream.rec(8, method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
        upstream.rec(9, status=200, cseq_method="BYE", branch="z9hG4bK-BYE", cseq=2, to_tag="TT-1"),
    ]


def late_offer_records() -> list[dict[str, Any]]:
    return [
        upstream.rec(1, method="INVITE"),
        upstream.rec(2, status=100, cseq_method="INVITE"),
        upstream.rec(3, status=200, cseq_method="INVITE", to_tag="TT-1", sdp_body=OFFER),
        upstream.rec(4, method="ACK", cseq=1, to_tag="TT-1", sdp_body=upstream.AUDIO_ANSWER),
    ]


def offer_only_records() -> list[dict[str, Any]]:
    return [upstream.rec(1, method="INVITE", sdp_body=OFFER)]


def _rtp_record(
    frame: int,
    *,
    stream: int,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    ssrc: int,
    sequence: int,
) -> dict[str, Any]:
    return {
        "source_reference": f"rtp-packet:{CAPTURE}:{frame}.1",
        "capture_file": CAPTURE,
        "capture_sha256": CAPTURE_SHA,
        "frame_number": frame,
        "frame_timestamp": f"1700000400.{frame:09d}",
        "frame_reference": f"frame:{frame}",
        "message_occurrence": 1,
        "protocol": "RTP",
        "fields": {
            "version": 2,
            "padding": False,
            "padding_count": 0,
            "extension": False,
            "extension_profile": None,
            "extension_length": None,
            "csrc_count": 0,
            "csrc": [],
            "marker": False,
            "payload_type": 0,
            "sequence_number": sequence,
            "timestamp": 160 * sequence,
            "ssrc": ssrc,
            "packet_length": 16,
            "udp_stream": stream,
            "udp_stream_packet": frame,
            "source_address": source,
            "destination_address": destination,
            "source_port": source_port,
            "destination_port": destination_port,
        },
    }


def fork_rtp_records() -> list[dict[str, Any]]:
    return [
        _rtp_record(1, stream=0, source="192.0.2.77", destination="192.0.2.10", source_port=6000, destination_port=49170, ssrc=0x11111111, sequence=1),
        _rtp_record(2, stream=0, source="192.0.2.77", destination="192.0.2.10", source_port=6000, destination_port=49170, ssrc=0x11111111, sequence=2),
        _rtp_record(3, stream=1, source="192.0.2.21", destination="192.0.2.77", source_port=49200, destination_port=7000, ssrc=0x22222222, sequence=1),
        _rtp_record(4, stream=2, source="192.0.2.22", destination="192.0.2.77", source_port=49200, destination_port=7002, ssrc=0x33333333, sequence=1),
        _rtp_record(5, stream=9, source="192.0.2.99", destination="192.0.2.98", source_port=6100, destination_port=49999, ssrc=0x99999999, sequence=1),
    ]


def late_rtp_records() -> list[dict[str, Any]]:
    return [
        _rtp_record(1, stream=0, source="192.0.2.77", destination="192.0.2.10", source_port=6000, destination_port=49170, ssrc=0x11111111, sequence=1),
        _rtp_record(2, stream=1, source="192.0.2.20", destination="192.0.2.77", source_port=49200, destination_port=7000, ssrc=0x22222222, sequence=1),
    ]


def offer_only_rtp_records() -> list[dict[str, Any]]:
    return [
        _rtp_record(1, stream=0, source="192.0.2.77", destination="192.0.2.10", source_port=6000, destination_port=49170, ssrc=0x11111111, sequence=1)
    ]


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_bundle(
    directory: Path,
    records: list[dict[str, Any]],
    rtp_records: list[dict[str, Any]],
    *,
    prefix: str = "media-session-",
    key: bytes | None = KEY,
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    events, transactions, dialogs = upstream.build_artifacts(records)
    event_path = directory / f"{prefix}events.jsonl"
    event_path.write_text(
        "\n".join(
            json.dumps(event, separators=(",", ":"), sort_keys=True)
            for event in events
        )
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
    session_path = directory / f"{prefix}ims-session.json"
    _write_json(session_path, session)

    sdp_records = [
        upstream.sdp_record(
            event["source_reference"],
            event["frame_number"],
            event["message_occurrence"],
            record["sdp_body"],
        )
        for record, event in zip(records, events)
        if record.get("sdp_body")
    ]
    sdp = sdp_model.build_analysis(
        sdp_records,
        input_name=f"{prefix}sdp-input.jsonl",
        endpoint_key=key,
    )
    sdp_path = directory / f"{prefix}sdp-analysis.json"
    _write_json(sdp_path, sdp)

    rtp_input = directory / f"{prefix}rtp-input.jsonl"
    rtp_input.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in rtp_records) + "\n",
        encoding="utf-8",
    )
    rtp_events, rtp_provenance = rtp_rtcp_model.extract_structured(
        rtp_input, endpoint_key=key
    )
    rtp = rtp_rtcp_model.build_analysis(rtp_events, rtp_provenance)
    rtp_path = directory / f"{prefix}rtp-rtcp-analysis.json"
    _write_json(rtp_path, rtp)

    correlation_provenance = sdp_rtp_transport_model.verify_provenance(
        sdp, rtp, sdp_path=sdp_path, rtp_path=rtp_path
    )
    correlation = sdp_rtp_transport_model.build_analysis(
        sdp, rtp, provenance=correlation_provenance
    )
    correlation_path = directory / f"{prefix}transport-correlation.json"
    _write_json(correlation_path, correlation)

    media_provenance = ims_media_signaling_model.verify_provenance(
        events,
        session,
        sdp,
        events_path=event_path,
        session_path=session_path,
        sdp_path=sdp_path,
    )
    media = ims_media_signaling_model.build_analysis(
        events, session, sdp, provenance=media_provenance
    )
    media_path = directory / f"{prefix}ims-media-signaling.json"
    _write_json(media_path, media)

    return {
        "events": event_path,
        "transactions": transaction_path,
        "dialogs": dialog_path,
        "session": session_path,
        "sdp": sdp_path,
        "rtp": rtp_path,
        "correlation": correlation_path,
        "media": media_path,
        "session_document": session,
        "sdp_document": sdp,
        "rtp_document": rtp,
        "correlation_document": correlation,
        "media_document": media,
        "event_document": events,
    }


def write_examples(directory: Path) -> dict[str, Any]:
    return build_bundle(
        directory,
        fork_terminated_records(),
        fork_rtp_records(),
        prefix="",
    )


if __name__ == "__main__":
    root = Path("skills/domain/ims-media-session")
    (root / "examples" / "inputs").mkdir(parents=True, exist_ok=True)
    write_examples(root / "examples" / "inputs")
    print("wrote IMS media session example inputs")