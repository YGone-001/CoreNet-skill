#!/usr/bin/env python3
"""Deterministic structured RTP/RTCP input records for Protocol tests."""

from __future__ import annotations

import json
from pathlib import Path

CAPTURE = "synthetic-rtp.pcapng"
SHA = "1" * 64


def rtp_fields(**overrides):
    fields = {
        "version": 2,
        "padding": False,
        "padding_count": 0,
        "extension": False,
        "extension_profile": None,
        "extension_length": None,
        "csrc_count": 0,
        "csrc": [],
        "marker": False,
        "payload_type": 96,
        "sequence_number": 1,
        "timestamp": 160,
        "ssrc": 0x01020304,
        "packet_length": 16,
        "udp_stream": 0,
        "udp_stream_packet": 1,
    }
    fields.update(overrides)
    return fields


def rtp(frame: int, **overrides):
    fields = rtp_fields(**overrides)
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


def sender_report(ssrc=0x01020304):
    return {
        "packet_type": 200,
        "version": 2,
        "length": 6,
        "report_count": 0,
        "sender_ssrc": ssrc,
        "sender_report": {
            "ntp_msw": 0,
            "ntp_lsw": 0,
            "ntp_present": True,
            "rtp_timestamp": 160,
            "packet_count": 10,
            "octet_count": 1000,
        },
        "report_blocks": [],
        "sdes_chunks": [],
        "bye_sources": [],
    }


def report_block(ssrc=0x01020304, fraction=0, cumulative=0, jitter=0):
    return {
        "reported_ssrc": ssrc,
        "fraction_lost": fraction,
        "cumulative_packets_lost": cumulative,
        "extended_highest_sequence": 10,
        "interarrival_jitter": jitter,
        "last_sr_timestamp": 0,
        "delay_since_last_sr": 0,
    }


def receiver_report(blocks, ssrc=0x01020305, report_count=None):
    if report_count is None:
        report_count = len(blocks)
    return {
        "packet_type": 201,
        "version": 2,
        "length": 7,
        "report_count": report_count,
        "sender_ssrc": ssrc,
        "report_blocks": blocks,
        "sdes_chunks": [],
        "bye_sources": [],
    }


def sdes(items, ssrc=0x01020304):
    return {
        "packet_type": 202,
        "version": 2,
        "length": 4,
        "report_count": 0,
        "sender_ssrc": ssrc,
        "source_count": 1,
        "sdes_chunks": [{"source_ssrc": ssrc, "items": items}],
        "report_blocks": [],
        "bye_sources": [],
    }


def item(item_type, length=8, text="secret-sdes-text"):
    return {
        "item_type": item_type,
        "value_present": True,
        "value_length": length,
        "text": text,
    }


def bye(sources, reason_present=True, reason_length=12, reason="secret-bye-reason"):
    return {
        "packet_type": 203,
        "version": 2,
        "length": 4,
        "report_count": 0,
        "source_count": len(sources),
        "bye_sources": sources,
        "bye_reason_present": reason_present,
        "bye_reason_length": reason_length,
        "reason": reason,
        "report_blocks": [],
        "sdes_chunks": [],
    }


def rtcp(frame: int, components, **overrides):
    record = {
        "source_reference": f"rtcp-packet:{CAPTURE}:{frame}.1",
        "capture_file": CAPTURE,
        "capture_sha256": SHA,
        "frame_number": frame,
        "frame_timestamp": f"1700000600.{frame:09d}",
        "frame_reference": f"frame:{frame}",
        "message_occurrence": 1,
        "protocol": "RTCP",
        "fields": {"components": components},
    }
    record.update(overrides)
    return record


def build_records() -> list[dict]:
    records: list[dict] = []
    frame = 1
    records.append(rtp(frame, payload_type=0, marker=True, packet_length=16))
    frame += 1
    records.append(rtp(frame, payload_type=96, packet_length=20))
    frame += 1
    records.append(rtp(frame, sequence_number=0, timestamp=0, packet_length=12))
    frame += 1
    records.append(rtp(frame, sequence_number=65535, timestamp=4294967295, packet_length=12))
    frame += 1
    records.append(rtp(frame, ssrc=4294967295, packet_length=12))
    frame += 1
    records.append(rtp(frame, csrc_count=3, csrc=[1, 2, 3], packet_length=24))
    frame += 1
    records.append(
        rtp(
            frame,
            extension=True,
            extension_profile=0xBEDE,
            extension_length=4,
            packet_length=20,
            extension_data="SECRET-EXTENSION-DATA",
        )
    )
    frame += 1
    records.append(rtp(frame, padding=True, padding_count=4, packet_length=20))
    frame += 1
    missing = rtp(frame)
    del missing["fields"]["sequence_number"]
    records.append(missing)
    frame += 1
    records.append(rtp(frame, payload_type=200, sequence_number=70000, packet_length=8))
    frame += 1
    records.append(rtp(frame, truncated=True, packet_length=12))
    frame += 1
    records.append(rtp(frame, version=3, packet_length=12))
    frame += 1
    records.append(rtp(frame, payload="SECRET-PAYLOAD-BYTES", packet_length=16))
    frame += 1
    records.append(rtcp(frame, [sender_report()]))
    frame += 1
    records.append(rtcp(frame, [receiver_report([report_block(fraction=10)])]))
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                receiver_report(
                    [report_block(ssrc=0x11111111, cumulative=5), report_block(ssrc=0x22222222, cumulative=-7)]
                )
            ],
        )
    )
    frame += 1
    records.append(
        rtcp(frame, [receiver_report([report_block(jitter=3200)], report_count=1)])
    )
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                sdes([item(1), item(2), item(3), item(4), item(5), item(6), item(7), item(8)])
            ],
        )
    )
    frame += 1
    records.append(rtcp(frame, [bye([0x01020304, 0x01020305])]))
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                sender_report(),
                receiver_report([report_block()]),
                sdes([item(1)]),
                bye([0x01020304], reason_present=False, reason_length=0),
            ],
        )
    )
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                sender_report(ssrc=0xAAAAAAAA),
                sender_report(ssrc=0xBBBBBBBB),
            ],
        )
    )
    frame += 1
    records.append(
        rtcp(frame, [{"packet_type": 204, "version": 2, "length": 4, "report_count": 0, "sender_ssrc": 1, "app_data": "SECRET-APP-DATA"}])
    )
    frame += 1
    records.append(rtcp(frame, [{"packet_type": 205, "version": 2, "length": 4, "report_count": 0, "sender_ssrc": 1}]))
    frame += 1
    records.append(rtcp(frame, [{"packet_type": 207, "version": 2, "length": 4, "report_count": 0, "sender_ssrc": 1}]))
    frame += 1
    records.append(rtcp(frame, [{"packet_type": 206, "version": 2, "length": 4, "report_count": 0, "sender_ssrc": 1}]))
    frame += 1
    records.append(rtcp(frame, [{"packet_type": 250, "version": 2, "length": 4, "report_count": 0, "sender_ssrc": 1}]))
    frame += 1
    records.append(rtcp(frame, [{"packet_type": 201, "version": 2, "length": 3, "report_count": 0, "sender_ssrc": 1, "malformed_length": True}]))
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                {
                    "packet_type": 201,
                    "version": 2,
                    "length": 7,
                    "report_count": 2,
                    "sender_ssrc": 1,
                    "report_blocks": [{"reported_ssrc": 2}],
                }
            ],
        )
    )
    frame += 1
    records.append(
        rtcp(
            frame,
            [
                sender_report(),
                {"packet_type": 201, "version": 2, "length": 7, "report_count": 0, "sender_ssrc": 1, "truncated": True},
            ],
        )
    )
    return records


def write_input(path: Path) -> None:
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in build_records()) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    write_input(Path("skills/protocol/sdp-rtp/examples/inputs/rtp-rtcp-cases.jsonl"))
    print(f"wrote {len(build_records())} records")