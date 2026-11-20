#!/usr/bin/env python3
"""Synthetic accepted RTP/RTCP Analysis fixtures for the rtp-stream tests.

Every fixture is synthetic and sanitized. No capture, raw address, raw port,
payload byte, subscriber identity or key material is produced or written.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CAPTURE = "synthetic-rtp.pcapng"
CAPTURE_SHA256 = "a" * 64
ENDPOINT_CONTEXT = "endpoint-context-hmac-sha256:v1:" + "c" * 64
SOURCE_ENDPOINT = "endpoint-hmac-sha256:v1:" + "1" * 64
SOURCE_ENDPOINT_SECOND = "endpoint-hmac-sha256:v1:" + "3" * 64
DESTINATION_ENDPOINT = "endpoint-hmac-sha256:v1:" + "2" * 64
AUTO = object()


def rtp_event(
    *,
    frame: int = 1,
    sequence: int | None = 100,
    occurrence: int = 1,
    udp_stream: int | None = 1,
    ssrc: int | None = 0x11112222,
    ssrc_reference: Any = AUTO,
    payload_type: int | None = 0,
    version: int | None = 2,
    status: str = "OBSERVED",
    capture: str = CAPTURE,
    capture_sha256: str = CAPTURE_SHA256,
    source_reference: str | None = None,
    source_endpoint: str | None = None,
    destination_endpoint: str | None = None,
    endpoint_status: str | None = None,
    frame_reference: str | None = None,
    invalid_reasons: list[str] | None = None,
) -> dict[str, Any]:
    if ssrc_reference is AUTO:
        ssrc_reference = (
            f"rtp-ssrc:{capture}:{ssrc:08x}" if ssrc is not None else None
        )
    event: dict[str, Any] = {
        "event_reference": source_reference
        or f"rtp-packet:{capture}:{frame}.{occurrence}",
        "capture_file": capture,
        "capture_sha256": capture_sha256,
        "frame_number": frame,
        "frame_timestamp": f"1700000000.{frame:06d}",
        "frame_reference": frame_reference if frame_reference is not None else f"frame:{frame}",
        "message_occurrence": occurrence,
        "protocol": "RTP",
        "parser_version": "0.4.0",
        "evidence_status": status,
        "version": version,
        "padding": False,
        "padding_count": 0,
        "extension": False,
        "extension_profile": None,
        "extension_length": None,
        "csrc_count": 0,
        "csrc": [],
        "marker": False,
        "payload_type": payload_type,
        "sequence_number": sequence,
        "timestamp": 1000 + frame,
        "ssrc": ssrc,
        "ssrc_reference": ssrc_reference,
        "packet_length": 200,
        "udp_stream": udp_stream,
        "udp_stream_packet": frame,
        "invalid_reasons": sorted(set(invalid_reasons or [])),
        "limitations": ["RTP payload bytes are never published"],
        "not_confirmed": ["RTP_DELIVERY", "TWO_WAY_AUDIO"],
    }
    if endpoint_status is not None:
        event["transport_endpoint_status"] = endpoint_status
        event["source_transport_endpoint_reference"] = source_endpoint
        event["destination_transport_endpoint_reference"] = destination_endpoint
    return event


def rtcp_sr_event(
    *,
    frame: int = 900,
    sender_ssrc: int = 0x12345678,
    udp_stream: int | None = 90,
    capture: str = CAPTURE,
    capture_sha256: str = CAPTURE_SHA256,
    status: str = "OBSERVED",
) -> dict[str, Any]:
    return {
        "event_reference": f"rtcp-component:{capture}:{frame}.1.0",
        "packet_reference": f"rtcp-packet:{capture}:{frame}.1",
        "capture_file": capture,
        "capture_sha256": capture_sha256,
        "frame_number": frame,
        "frame_timestamp": f"1700000000.{frame:06d}",
        "frame_reference": f"frame:{frame}",
        "message_occurrence": 1,
        "protocol": "RTCP",
        "component_index": 0,
        "packet_type": 200,
        "packet_type_name": "SR",
        "version": 2,
        "length": 6,
        "report_count": 0,
        "sender_ssrc": sender_ssrc,
        "sender_ssrc_reference": f"rtp-ssrc:{capture}:{sender_ssrc:08x}",
        "sender_report": {
            "ntp_msw": 1,
            "ntp_lsw": 2,
            "ntp_present": True,
            "rtp_timestamp": 3,
            "packet_count": 10,
            "octet_count": 1000,
        },
        "report_blocks": [],
        "sdes_chunks": [],
        "bye_sources": [],
        "bye_source_count": 0,
        "bye_reason_present": False,
        "bye_reason_length": 0,
        "udp_stream": udp_stream,
        "udp_stream_packet": 1,
        "evidence_status": status,
        "invalid_reasons": [],
        "limitations": ["RTCP report values are remote-reported protocol values"],
        "not_confirmed": ["LOCAL_PACKET_LOSS", "MEDIA_QOS"],
        "declared_source_count": None,
        "observed_source_count": 0,
        "source_count_status": "NOT_APPLICABLE",
    }


def rtcp_bye_event(
    *,
    frame: int = 901,
    source_ssrc: int = 0x11112222,
    capture: str = CAPTURE,
    capture_sha256: str = CAPTURE_SHA256,
    status: str = "OBSERVED",
) -> dict[str, Any]:
    event = rtcp_sr_event(
        frame=frame,
        sender_ssrc=source_ssrc,
        udp_stream=None,
        capture=capture,
        capture_sha256=capture_sha256,
        status=status,
    )
    event.update(
        {
            "packet_type": 203,
            "packet_type_name": "BYE",
            "length": 1,
            "sender_report": None,
            "bye_sources": [source_ssrc],
            "bye_source_count": 1,
            "declared_source_count": 1,
            "observed_source_count": 1,
            "source_count_status": "OBSERVED",
        }
    )
    return event


def analysis(
    events: list[dict[str, Any]],
    *,
    capture: str = CAPTURE,
    capture_sha256: str = CAPTURE_SHA256,
    endpoint_context: Any = AUTO,
    **overrides: Any,
) -> dict[str, Any]:
    rtp = [event for event in events if event.get("protocol") == "RTP"]
    rtcp = [event for event in events if event.get("protocol") == "RTCP"]
    if endpoint_context is AUTO:
        endpoint_context = (
            ENDPOINT_CONTEXT
            if any("transport_endpoint_status" in event for event in rtp)
            else None
        )
    provenance: dict[str, Any] = {
        "mode": "STRUCTURED_JSONL",
        "input_name": "synthetic-rtp-cases.jsonl",
        "capture_files": [capture],
        "capture_sha256": capture_sha256,
        "input_message_count": len(events),
        "parser_version": "0.4.0",
        "tool": None,
        "decode_as": [],
    }
    if endpoint_context is not None:
        provenance["endpoint_context_reference"] = endpoint_context
    document: dict[str, Any] = {
        "analysis_name": "rtp-rtcp",
        "analysis_version": "0.4.0",
        "event_schema_version": "1.2.0",
        "capability": "bounded RTP and RTCP packet evidence with optional endpoint references",
        "input_provenance": provenance,
        "event_count": len(events),
        "events": events,
        "completeness": {
            "rtp_packet_count": len(rtp),
            "rtcp_component_count": len(rtcp),
            "sr_component_count": sum(1 for event in rtcp if event.get("packet_type") == 200),
            "rr_component_count": sum(1 for event in rtcp if event.get("packet_type") == 201),
            "sdes_component_count": sum(1 for event in rtcp if event.get("packet_type") == 202),
            "bye_component_count": sum(1 for event in rtcp if event.get("packet_type") == 203),
            "unsupported_component_count": sum(
                1 for event in events if event.get("evidence_status") == "UNSUPPORTED"
            ),
            "observed_event_count": sum(
                1 for event in events if event.get("evidence_status") == "OBSERVED"
            ),
            "incomplete_event_count": sum(
                1 for event in events if event.get("evidence_status") == "INCOMPLETE"
            ),
            "ambiguous_event_count": sum(
                1 for event in events if event.get("evidence_status") == "AMBIGUOUS"
            ),
            "unsupported_event_count": sum(
                1 for event in events if event.get("evidence_status") == "UNSUPPORTED"
            ),
            "invalid_event_count": sum(
                1 for event in events if event.get("evidence_status") == "INVALID"
            ),
        },
        "limitations": ["RTP payload, SDES text and key material are never published"],
        "not_confirmed": ["RTP_DELIVERY", "MEDIA_QOS"],
    }
    if endpoint_context is not None:
        document["endpoint_context_reference"] = endpoint_context
    document.update(overrides)
    return document


def write_json(document: dict[str, Any], path: Path) -> Path:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def stream(
    sequences: list[int],
    *,
    udp_stream: int = 1,
    ssrc: int = 0x11112222,
    start_frame: int = 1,
    payload_types: list[int] | None = None,
    statuses: list[str] | None = None,
    **event_options: Any,
) -> list[dict[str, Any]]:
    """Build a sequential RTP event list for one stream."""
    events: list[dict[str, Any]] = []
    for index, sequence in enumerate(sequences):
        payload_type = (
            payload_types[index]
            if payload_types is not None and index < len(payload_types)
            else 0
        )
        status = (
            statuses[index] if statuses is not None and index < len(statuses) else "OBSERVED"
        )
        events.append(
            rtp_event(
                frame=start_frame + index,
                sequence=sequence,
                udp_stream=udp_stream,
                ssrc=ssrc,
                payload_type=payload_type,
                status=status,
                **event_options,
            )
        )
    return events