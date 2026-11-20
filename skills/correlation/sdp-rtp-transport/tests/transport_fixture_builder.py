#!/usr/bin/env python3
"""Deterministic synthetic SDP and RTP/RTCP artifacts for transport tests."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SKILL = Path(__file__).resolve().parents[1]
SKILLS = SKILL.parents[1]
SDP_SCRIPTS = SKILLS / "protocol" / "sdp-rtp" / "scripts"
for path in (SDP_SCRIPTS, SKILL / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402

CAPTURE = "synthetic-sdp-rtp-transport.pcapng"
SHA = "c4" * 32
TEST_KEY = hashlib.sha256(b"synthetic-transport-correlation-test-key").digest()


def body(lines: list[str]) -> str:
    return "\r\n".join(lines) + "\r\n"


SDP_CASES: list[tuple[str, str]] = [
    (
        "basic-offer",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.10",
                "s=Synthetic Basic",
                "c=IN IP4 192.0.2.10",
                "t=0 0",
                "m=audio 49170 RTP/AVP 0",
            ]
        ),
    ),
    (
        "ipv6-and-inherited",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.10",
                "s=Synthetic Override",
                "c=IN IP4 192.0.2.10",
                "t=0 0",
                "m=audio 49172 RTP/AVP 0",
                "c=IN IP6 2001:db8::10",
                "m=audio 49174 RTP/AVP 0",
            ]
        ),
    ),
    (
        "unsupported-media",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.50",
                "s=Synthetic Unsupported",
                "c=IN IP4 192.0.2.50",
                "t=0 0",
                "m=audio 0 RTP/AVP 0",
                "m=audio 5000 RTP/AVP 0",
                "a=candidate:1 1 udp 2122260223 192.0.2.50 5000 typ host",
                "m=audio 5002 RTP/AVP 0",
                "c=IN IP4 239.1.1.1/127",
            ]
        ),
    ),
    (
        "bundle-shared",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.30",
                "s=Synthetic Bundle",
                "c=IN IP4 192.0.2.30",
                "t=0 0",
                "a=group:BUNDLE 0 1",
                "m=audio 5000 RTP/AVP 0",
                "a=mid:0",
                "m=video 5000 RTP/AVP 96",
                "a=mid:1",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "unrelated-shared",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.40",
                "s=Synthetic Shared",
                "c=IN IP4 192.0.2.40",
                "t=0 0",
                "m=audio 5002 RTP/AVP 0",
                "m=video 5002 RTP/AVP 96",
                "a=rtpmap:96 H264/90000",
            ]
        ),
    ),
    (
        "unmatched-media",
        body(
            [
                "v=0",
                "o=- 1000 1 IN IP4 192.0.2.60",
                "s=Synthetic Unmatched",
                "c=IN IP4 192.0.2.60",
                "t=0 0",
                "m=audio 6000 RTP/AVP 0",
            ]
        ),
    ),
]


def sdp_records() -> list[dict[str, Any]]:
    records = []
    for index, (_name, sdp_body) in enumerate(SDP_CASES, start=1):
        records.append(
            {
                "source_reference": f"sip-body:{CAPTURE}:{index}.1",
                "capture_file": CAPTURE,
                "capture_sha256": SHA,
                "frame_number": index,
                "frame_reference": f"frame:{index}",
                "message_occurrence": 1,
                "sdp_body": sdp_body,
            }
        )
    return records


def sdp_analysis(key: bytes | None = TEST_KEY) -> dict[str, Any]:
    return sdp_model.build_analysis(
        sdp_records(), input_name="transport-sdp-input.jsonl", endpoint_key=key
    )


def _rtp_fields(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
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
        "sequence_number": 1,
        "timestamp": 160,
        "ssrc": 0x01020304,
        "packet_length": 16,
        "udp_stream": 0,
        "udp_stream_packet": 1,
    }
    fields.update(overrides)
    return fields


def rtp_record(
    frame: int,
    *,
    stream: int,
    source_address: str,
    destination_address: str,
    source_port: int,
    destination_port: int,
    ssrc: int = 0x01020304,
    sequence_number: int = 1,
    evidence: str = "OBSERVED",
) -> dict[str, Any]:
    fields = _rtp_fields(
        udp_stream=stream,
        udp_stream_packet=frame,
        ssrc=ssrc,
        sequence_number=sequence_number,
        source_address=source_address,
        destination_address=destination_address,
        source_port=source_port,
        destination_port=destination_port,
    )
    if evidence == "INCOMPLETE":
        fields.pop("sequence_number", None)
    return {
        "source_reference": f"rtp-packet:{CAPTURE}:{frame}.1",
        "capture_file": CAPTURE,
        "capture_sha256": SHA,
        "frame_number": frame,
        "frame_timestamp": f"1700000600.{frame:09d}",
        "frame_reference": f"frame:{frame}",
        "message_occurrence": 1,
        "protocol": "RTP",
        "fields": fields,
    }


def rtp_records() -> list[dict[str, Any]]:
    return [
        rtp_record(1, stream=0, source_address="192.0.2.20", destination_address="192.0.2.10", source_port=6000, destination_port=49170),
        rtp_record(2, stream=0, source_address="192.0.2.20", destination_address="192.0.2.10", source_port=6000, destination_port=49170, sequence_number=2),
        rtp_record(3, stream=1, source_address="192.0.2.99", destination_address="192.0.2.30", source_port=6002, destination_port=5000),
        rtp_record(4, stream=1, source_address="192.0.2.99", destination_address="192.0.2.30", source_port=6002, destination_port=5000, sequence_number=2),
        rtp_record(5, stream=2, source_address="2001:db8::20", destination_address="2001:db8::10", source_port=6004, destination_port=49172),
        rtp_record(6, stream=3, source_address="192.0.2.20", destination_address="192.0.2.10", source_port=6006, destination_port=49174),
        rtp_record(7, stream=4, source_address="192.0.2.99", destination_address="192.0.2.40", source_port=6008, destination_port=5002),
        rtp_record(8, stream=9, source_address="192.0.2.99", destination_address="192.0.2.77", source_port=6010, destination_port=7000),
        rtp_record(9, stream=10, source_address="192.0.2.20", destination_address="192.0.2.10", source_port=6012, destination_port=49170, evidence="INCOMPLETE"),
    ]


def _write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rtp_analysis(key: bytes | None = TEST_KEY) -> dict[str, Any]:
    directory = Path(__file__).resolve().parent
    input_path = directory / ".rtp-input.jsonl"
    try:
        input_path.write_text(
            "\n".join(
                json.dumps(record, sort_keys=True) for record in rtp_records()
            )
            + "\n",
            encoding="utf-8",
        )
        events, provenance = rtp_rtcp_model.extract_structured(
            input_path, endpoint_key=key
        )
    finally:
        input_path.unlink(missing_ok=True)
    return rtp_rtcp_model.build_analysis(events, provenance)


def build_artifacts() -> tuple[dict[str, Any], dict[str, Any]]:
    return (sdp_analysis(), rtp_analysis())


def write_examples(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    sdp = sdp_analysis()
    rtp = rtp_analysis()
    sdp_path = directory / "transport-sdp-analysis.json"
    rtp_path = directory / "transport-rtp-rtcp-analysis.json"
    _write_json(sdp_path, sdp)
    _write_json(rtp_path, rtp)
    return (sdp_path, rtp_path)


if __name__ == "__main__":
    root = Path("skills/correlation/sdp-rtp-transport")
    write_examples(root / "examples" / "inputs")
    print("wrote correlation example inputs")